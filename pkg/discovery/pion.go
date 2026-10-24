package discovery

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/pion/logging"
	"github.com/pion/mdns/v2"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// errNoMulticastSocket is returned when neither an IPv4 nor an IPv6 mDNS
// socket could be opened.
var errNoMulticastSocket = errors.New("discovery: failed to open any mDNS multicast socket")

// newPionConn opens an mDNS connection bound to the standard multicast
// groups. IPv4 or IPv6 may be unavailable on a host; either alone suffices.
func newPionConn(opts ...mdns.ServerOption) (*mdns.Conn, error) {
	var pc4 *ipv4.PacketConn
	if addr, err := net.ResolveUDPAddr("udp4", mdns.DefaultAddressIPv4); err == nil {
		if l, err := net.ListenUDP("udp4", addr); err == nil {
			pc4 = ipv4.NewPacketConn(l)
		}
	}

	var pc6 *ipv6.PacketConn
	if addr, err := net.ResolveUDPAddr("udp6", mdns.DefaultAddressIPv6); err == nil {
		if l, err := net.ListenUDP("udp6", addr); err == nil {
			pc6 = ipv6.NewPacketConn(l)
		}
	}

	if pc4 == nil && pc6 == nil {
		return nil, errNoMulticastSocket
	}

	conn, err := mdns.NewServer(pc4, pc6, opts...)
	if err != nil {
		if pc4 != nil {
			_ = pc4.Close()
		}
		if pc6 != nil {
			_ = pc6.Close()
		}
		return nil, err
	}
	return conn, nil
}

// pionServerFactory is the production MDNSServerFactory using pion/mdns.
// Each registration gets its own mDNS connection so it can be withdrawn
// independently.
type pionServerFactory struct {
	loggerFactory logging.LoggerFactory

	once     sync.Once
	hostName string
}

// pionServer adapts *mdns.Conn to MDNSServer.
type pionServer struct {
	conn *mdns.Conn
}

func (s *pionServer) Shutdown() {
	_ = s.conn.Close()
}

// defaultHostName returns a random host name, generated once per factory so
// all services of a node share the same SRV target. Matter recommends a
// 12 hex character name derived from the MAC address (Spec Section 4.3.4);
// a random value of the same shape is used when none is configured.
func (f *pionServerFactory) defaultHostName() string {
	f.once.Do(func() {
		var buf [6]byte
		_, _ = rand.Read(buf[:])
		f.hostName = strings.ToUpper(hex.EncodeToString(buf[:]))
	})
	return f.hostName
}

func (f *pionServerFactory) Register(reg ServiceRegistration) (MDNSServer, error) {
	host := strings.TrimSuffix(reg.HostName, ".")
	if host == "" {
		host = f.defaultHostName()
	}
	if !strings.HasSuffix(strings.ToLower(host), ".local") {
		host += ".local"
	}

	text := make([]mdns.TXTEntry, 0, len(reg.Text))
	for _, kv := range reg.Text {
		key, value, _ := strings.Cut(kv, "=")
		text = append(text, mdns.NewTXTString(key, value))
	}

	opts := []mdns.ServerOption{
		mdns.WithLocalNames(host),
		mdns.WithService(mdns.ServiceInstance{
			Instance: reg.Instance,
			Service:  reg.Service,
			Domain:   strings.TrimSuffix(reg.Domain, "."),
			Host:     host + ".",
			Port:     uint16(reg.Port),
			Text:     text,
			Subtypes: reg.Subtypes,
		}),
	}
	if reg.Interfaces != nil {
		opts = append(opts, mdns.WithInterfaces(reg.Interfaces...))
	}
	if f.loggerFactory != nil {
		opts = append(opts, mdns.WithLoggerFactory(f.loggerFactory))
	}

	conn, err := newPionConn(opts...)
	if err != nil {
		return nil, err
	}
	return &pionServer{conn: conn}, nil
}

// pionResolver is the production MDNSResolver using pion/mdns.
// pion/mdns reports discoveries through a single per-connection handler, so
// each Browse or Lookup uses its own connection.
type pionResolver struct {
	loggerFactory logging.LoggerFactory
}

func newPionResolver(loggerFactory logging.LoggerFactory) *pionResolver {
	return &pionResolver{loggerFactory: loggerFactory}
}

func (r *pionResolver) Browse(ctx context.Context, service, domain string, entries chan<- *ServiceEntry) error {
	return r.browse(ctx, service, "", entries)
}

// Lookup resolves a single instance by browsing its service type and
// filtering on the instance name.
func (r *pionResolver) Lookup(ctx context.Context, instance, service, domain string, entries chan<- *ServiceEntry) error {
	return r.browse(ctx, service, instance, entries)
}

// browse runs a pion/mdns browse until ctx is done, sending an entry each
// time an instance is first resolved or gains addresses. If instance is
// non-empty, other instances are ignored.
func (r *pionResolver) browse(ctx context.Context, service, instance string, entries chan<- *ServiceEntry) error {
	var opts []mdns.ServerOption
	if r.loggerFactory != nil {
		opts = append(opts, mdns.WithLoggerFactory(r.loggerFactory))
	}

	conn, err := newPionConn(opts...)
	if err != nil {
		return err
	}
	defer conn.Close()

	events := make(chan mdns.ServiceEvent, 16)
	conn.OnServiceDiscovered(func(evt mdns.ServiceEvent) {
		select {
		case events <- evt:
		case <-ctx.Done():
		}
	})

	if err := conn.Browse(ctx, service); err != nil {
		return err
	}

	known := make(map[string]*ServiceEntry)
	for {
		select {
		case <-ctx.Done():
			return nil
		case evt := <-events:
			if instance != "" && !strings.EqualFold(evt.Instance.Instance, instance) {
				continue
			}
			entry, changed := mergeServiceEvent(known, evt)
			if !changed {
				continue
			}
			select {
			case entries <- entry:
			case <-ctx.Done():
				return nil
			}
		}
	}
}

// mergeServiceEvent folds evt into the entry tracked for its instance and
// returns a snapshot of that entry, plus whether anything new was learned.
func mergeServiceEvent(known map[string]*ServiceEntry, evt mdns.ServiceEvent) (*ServiceEntry, bool) {
	key := strings.ToLower(evt.Instance.Instance)
	entry, ok := known[key]
	changed := !ok
	if !ok {
		entry = &ServiceEntry{}
		known[key] = entry
	}

	text := make([]string, 0, len(evt.Instance.Text))
	for _, kv := range evt.Instance.Text {
		text = append(text, kv.Key+"="+string(kv.Value))
	}

	if entry.HostName != evt.Instance.Host || entry.Port != int(evt.Instance.Port) ||
		strings.Join(entry.Text, "\x00") != strings.Join(text, "\x00") {
		changed = true
	}
	entry.Instance = evt.Instance.Instance
	entry.Service = evt.Instance.Service
	entry.Domain = evt.Instance.Domain
	entry.HostName = evt.Instance.Host
	entry.Port = int(evt.Instance.Port)
	entry.Text = text

	if addEntryAddr(entry, evt.Addr) {
		changed = true
	}

	snapshot := *entry
	snapshot.AddrIPv4 = append([]net.IP(nil), entry.AddrIPv4...)
	snapshot.AddrIPv6 = filterZonedLinkLocal(entry.AddrIPv6, len(entry.AddrIPv4) > 0)
	return &snapshot, changed
}

// addEntryAddr adds addr to entry if not already present.
func addEntryAddr(entry *ServiceEntry, addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	ip := net.IP(addr.Unmap().AsSlice())

	list := &entry.AddrIPv6
	if addr.Unmap().Is4() {
		list = &entry.AddrIPv4
	}
	for _, existing := range *list {
		if existing.Equal(ip) {
			return false
		}
	}
	*list = append(*list, ip)
	return true
}

// filterZonedLinkLocal drops IPv6 link-local addresses when other usable
// addresses exist. ResolvedService carries net.IP, which cannot hold the
// interface zone a link-local address needs to be dialed, so preferring one
// over a global, ULA or IPv4 address would make connection attempts fail.
func filterZonedLinkLocal(ips []net.IP, haveIPv4 bool) []net.IP {
	var routable, linkLocal []net.IP
	for _, ip := range ips {
		if ip.IsLinkLocalUnicast() {
			linkLocal = append(linkLocal, ip)
		} else {
			routable = append(routable, ip)
		}
	}
	if len(routable) > 0 || haveIPv4 {
		return routable
	}
	return linkLocal
}
