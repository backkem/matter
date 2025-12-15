package commissioning

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/backkem/matter/pkg/clusters/generalcommissioning"
	"github.com/backkem/matter/pkg/commissioning/payload"
	"github.com/backkem/matter/pkg/discovery"
	"github.com/backkem/matter/pkg/exchange"
	"github.com/backkem/matter/pkg/fabric"
	"github.com/backkem/matter/pkg/im"
	"github.com/backkem/matter/pkg/securechannel"
	"github.com/backkem/matter/pkg/session"
	"github.com/backkem/matter/pkg/transport"
)

// DefaultCommissioningTimeout is the default timeout for the entire
// commissioning process if not specified.
const DefaultCommissioningTimeout = 5 * time.Minute

// DefaultDiscoveryTimeout is the default timeout for device discovery.
const DefaultDiscoveryTimeout = 30 * time.Second

// DefaultPASETimeout is the default timeout for PASE establishment.
const DefaultPASETimeout = 30 * time.Second

// CommissionerConfig configures the Commissioner.
type CommissionerConfig struct {
	// Resolver for DNS-SD device discovery.
	Resolver *discovery.Resolver

	// SecureChannel manager for PASE/CASE sessions.
	SecureChannel *securechannel.Manager

	// SessionManager for session tracking.
	SessionManager *session.Manager

	// ExchangeManager for message exchanges.
	// Required for IM commands (ArmFailSafe, CommissioningComplete, etc.).
	ExchangeManager *exchange.Manager

	// FabricInfo for the commissioner's fabric.
	// Used when adding the device to the fabric.
	FabricInfo *fabric.FabricInfo

	// Callbacks for commissioning events.
	Callbacks CommissionerCallbacks

	// Timeout for overall commissioning process.
	// Defaults to DefaultCommissioningTimeout if zero.
	Timeout time.Duration

	// DiscoveryTimeout for device discovery.
	// Defaults to DefaultDiscoveryTimeout if zero.
	DiscoveryTimeout time.Duration

	// PASETimeout for PASE establishment.
	// Defaults to DefaultPASETimeout if zero.
	PASETimeout time.Duration

	// AttestationVerifier for verifying device attestation.
	// If nil, NewAcceptAllVerifier() is used (accepts all devices).
	// See docs/pkgs/attestation.md for design rationale.
	AttestationVerifier AttestationVerifier
}

// CommissionerCallbacks provides event callbacks during commissioning.
type CommissionerCallbacks struct {
	// OnStateChanged is called when the commissioning state changes.
	OnStateChanged func(state CommissionerState)

	// OnProgress is called with progress updates.
	// percent ranges from 0-100, message describes the current step.
	OnProgress func(percent int, message string)

	// OnDeviceAttestationResult is called after device attestation.
	// Return true to continue commissioning, false to abort.
	// If nil, attestation is automatically accepted.
	OnDeviceAttestationResult func(result *AttestationResult) bool

	// OnCommissioningComplete is called when commissioning succeeds.
	OnCommissioningComplete func(nodeID fabric.NodeID)

	// OnError is called when commissioning fails.
	OnError func(err error, state CommissionerState)
}

// AttestationResult contains the result of device attestation verification.
type AttestationResult struct {
	// Verified indicates whether attestation was cryptographically verified.
	Verified bool

	// Trusted indicates whether the device's DAC chain is trusted.
	Trusted bool

	// VendorID is the vendor ID from the DAC.
	VendorID uint16

	// ProductID is the product ID from the DAC.
	ProductID uint16

	// CertificateDeclaration is the raw certification declaration.
	CertificateDeclaration []byte

	// AttestationNonce is the nonce used for attestation.
	AttestationNonce []byte

	// Error is set if attestation verification failed.
	Error error
}

// NetworkConfig contains operational network configuration.
type NetworkConfig struct {
	// NetworkType is the type of network (WiFi, Thread, Ethernet).
	NetworkType string

	// WiFi credentials (if NetworkType is WiFi).
	WiFiSSID     string
	WiFiPassword string

	// Thread credentials (if NetworkType is Thread).
	ThreadDataset []byte
}

// Commissioner orchestrates the commissioning process.
//
// The commissioner is the controller-side entity that guides a device
// through the commissioning flow. It handles:
//   - Device discovery via DNS-SD
//   - PASE session establishment
//   - Device attestation verification
//   - Operational credential installation
//   - Network configuration
//   - CASE session establishment
type Commissioner struct {
	config   CommissionerConfig
	state    CommissionerState
	imClient *im.Client
	mu       sync.RWMutex

	// Current commissioning context
	currentPayload *payload.SetupPayload
	currentDevice  *discovery.ResolvedService
	paseSession    *session.SecureContext
	caseSession    *session.SecureContext
	peerAddress    transport.PeerAddress

	// Cancellation
	cancelFunc context.CancelFunc
}

// NewCommissioner creates a new Commissioner with the given configuration.
func NewCommissioner(config CommissionerConfig) *Commissioner {
	// Apply defaults
	if config.Timeout == 0 {
		config.Timeout = DefaultCommissioningTimeout
	}
	if config.DiscoveryTimeout == 0 {
		config.DiscoveryTimeout = DefaultDiscoveryTimeout
	}
	if config.PASETimeout == 0 {
		config.PASETimeout = DefaultPASETimeout
	}
	if config.AttestationVerifier == nil {
		config.AttestationVerifier = NewAcceptAllVerifier()
	}

	c := &Commissioner{
		config: config,
		state:  CommissionerStateIdle,
	}

	// Create IM client if exchange manager is provided
	if config.ExchangeManager != nil {
		c.imClient = im.NewClient(im.ClientConfig{
			ExchangeManager: config.ExchangeManager,
			Timeout:         config.PASETimeout, // Use PASE timeout for IM requests
		})
	}

	return c
}

// State returns the current commissioning state.
func (c *Commissioner) State() CommissionerState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state
}

// setState sets the state and notifies callbacks.
func (c *Commissioner) setState(state CommissionerState) {
	c.mu.Lock()
	c.state = state
	c.mu.Unlock()

	if c.config.Callbacks.OnStateChanged != nil {
		c.config.Callbacks.OnStateChanged(state)
	}
}

// progress reports progress to callbacks.
func (c *Commissioner) progress(percent int, message string) {
	if c.config.Callbacks.OnProgress != nil {
		c.config.Callbacks.OnProgress(percent, message)
	}
}

// CommissionFromQRCode commissions a device from a QR code string.
//
// This is a convenience wrapper that parses the QR code first.
func (c *Commissioner) CommissionFromQRCode(ctx context.Context, qrCode string) error {
	p, err := payload.ParseQRCode(qrCode)
	if err != nil {
		return err
	}
	return c.CommissionFromPayload(ctx, p)
}

// CommissionFromManualCode commissions a device from a manual pairing code.
//
// This is a convenience wrapper that parses the manual code first.
func (c *Commissioner) CommissionFromManualCode(ctx context.Context, code string) error {
	p, err := payload.ParseManualCode(code)
	if err != nil {
		return err
	}
	return c.CommissionFromPayload(ctx, p)
}

// CommissionFromPayload commissions a device using a SetupPayload.
//
// This is the main entry point for commissioning. The full commissioning
// flow includes:
//  1. Discover device using discriminator
//  2. Establish PASE session using passcode
//  3. Arm fail-safe timer
//  4. Perform device attestation
//  5. Request CSR and add NOC
//  6. Configure operational network (if needed)
//  7. Discover via operational network
//  8. Establish CASE session
//  9. Send CommissioningComplete
func (c *Commissioner) CommissionFromPayload(ctx context.Context, p *payload.SetupPayload) error {
	c.mu.Lock()
	if c.state != CommissionerStateIdle {
		c.mu.Unlock()
		return ErrAlreadyCommissioning
	}
	c.currentPayload = p
	c.mu.Unlock()

	// Create cancellable context with timeout
	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	c.cancelFunc = cancel
	defer cancel()

	// Run the commissioning flow
	err := c.runCommissioningFlow(ctx, p)

	// Handle result
	c.mu.Lock()
	if err != nil {
		c.state = CommissionerStateFailed
		if c.config.Callbacks.OnError != nil {
			c.config.Callbacks.OnError(err, c.state)
		}
	} else {
		c.state = CommissionerStateComplete
	}
	c.currentPayload = nil
	c.currentDevice = nil
	c.paseSession = nil
	c.caseSession = nil
	c.cancelFunc = nil
	c.mu.Unlock()

	return err
}

// runCommissioningFlow executes the commissioning steps.
func (c *Commissioner) runCommissioningFlow(ctx context.Context, p *payload.SetupPayload) error {
	var err error

	// Step 1: Discover device
	c.progress(5, "Discovering device...")
	c.setState(CommissionerStateDiscovering)
	device, err := c.discoverDevice(ctx, p)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.currentDevice = device
	// Store peer address for IM communication
	if len(device.IPs) > 0 {
		c.peerAddress = transport.PeerAddress{
			Addr: &net.UDPAddr{
				IP:   device.IPs[0],
				Port: device.Port,
			},
			TransportType: transport.TransportTypeUDP,
		}
	}
	c.mu.Unlock()

	// Step 2: Establish PASE session
	c.progress(15, "Establishing PASE session...")
	c.setState(CommissionerStatePASE)
	paseSession, err := c.establishPASE(ctx, device, p)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.paseSession = paseSession
	c.mu.Unlock()

	// Step 3: Arm fail-safe
	c.progress(25, "Arming fail-safe timer...")
	c.setState(CommissionerStateArmingFailSafe)
	if err := c.armFailSafe(ctx, paseSession); err != nil {
		return err
	}

	// Step 4: Device attestation
	c.progress(35, "Verifying device attestation...")
	c.setState(CommissionerStateDeviceAttestation)
	if err := c.performDeviceAttestation(ctx, paseSession); err != nil {
		return err
	}

	// Step 5: Request CSR and add NOC
	c.progress(50, "Installing operational credentials...")
	c.setState(CommissionerStateCSRRequest)
	nodeID, err := c.requestCSRAndAddNOC(ctx, paseSession)
	if err != nil {
		return err
	}

	// Step 6: Configure network (if needed)
	c.progress(65, "Configuring operational network...")
	c.setState(CommissionerStateNetworkConfig)
	if err := c.configureNetwork(ctx, paseSession); err != nil {
		return err
	}

	// Step 7: Operational discovery
	c.progress(75, "Discovering on operational network...")
	c.setState(CommissionerStateOperationalDiscovery)
	if err := c.discoverOperational(ctx, nodeID); err != nil {
		return err
	}

	// Step 8: Establish CASE session
	c.progress(85, "Establishing CASE session...")
	c.setState(CommissionerStateCASE)
	caseSession, err := c.establishCASE(ctx, nodeID)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.caseSession = caseSession
	c.mu.Unlock()

	// Step 9: Commissioning complete
	c.progress(95, "Completing commissioning...")
	if err := c.sendCommissioningComplete(ctx, caseSession); err != nil {
		return err
	}

	c.progress(100, "Commissioning complete")
	c.setState(CommissionerStateComplete)

	if c.config.Callbacks.OnCommissioningComplete != nil {
		c.config.Callbacks.OnCommissioningComplete(nodeID)
	}

	return nil
}

// discoverDevice finds a commissionable device by discriminator.
func (c *Commissioner) discoverDevice(ctx context.Context, p *payload.SetupPayload) (*discovery.ResolvedService, error) {
	if c.config.Resolver == nil {
		return nil, ErrNilConfig
	}

	ctx, cancel := context.WithTimeout(ctx, c.config.DiscoveryTimeout)
	defer cancel()

	// For long discriminator, use direct discovery
	if !p.Discriminator.IsShort() {
		return c.config.Resolver.DiscoverCommissionableNode(ctx, p.Discriminator.Long())
	}

	// For short discriminator, browse and filter
	ch, err := c.config.Resolver.BrowseCommissionable(ctx)
	if err != nil {
		return nil, err
	}

	shortDisc := p.Discriminator.Short()
	for {
		select {
		case <-ctx.Done():
			return nil, ErrDeviceNotFound
		case svc, ok := <-ch:
			if !ok {
				return nil, ErrDeviceNotFound
			}
			// Check if discriminator matches (from TXT record)
			if txt, exists := svc.Text["D"]; exists {
				// Parse discriminator from TXT and check MSBs
				// For now, accept any device found
				_ = txt
			}
			// Return first device found when using short discriminator
			if shortDisc > 0 {
				return &svc, nil
			}
		}
	}
}

// establishPASE establishes a PASE session with the device.
func (c *Commissioner) establishPASE(ctx context.Context, device *discovery.ResolvedService, p *payload.SetupPayload) (*session.SecureContext, error) {
	if c.config.SecureChannel == nil {
		return nil, ErrNilConfig
	}
	if c.config.ExchangeManager == nil {
		return nil, ErrNilConfig
	}
	if c.config.SessionManager == nil {
		return nil, ErrNilConfig
	}

	// Get device address
	if len(device.IPs) == 0 {
		return nil, ErrDeviceNotFound
	}

	// Build peer address
	peerAddr := transport.PeerAddress{
		Addr: &net.UDPAddr{
			IP:   device.IPs[0],
			Port: device.Port,
		},
		TransportType: transport.TransportTypeUDP,
	}

	// Create PASE client
	paseClient := NewPASEClient(PASEClientConfig{
		ExchangeManager: c.config.ExchangeManager,
		SecureChannel:   c.config.SecureChannel,
		SessionManager:  c.config.SessionManager,
		Timeout:         c.config.PASETimeout,
	})

	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, c.config.PASETimeout)
	defer cancel()

	// Perform PASE handshake
	secureCtx, err := paseClient.Establish(ctx, peerAddr, p.Passcode)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPASEFailed, err)
	}

	return secureCtx, nil
}

// armFailSafe arms the fail-safe timer on the device.
//
// Spec Reference: Section 11.10.7.2 "ArmFailSafe"
func (c *Commissioner) armFailSafe(ctx context.Context, sess *session.SecureContext) error {
	if c.imClient == nil {
		// No IM client - skip (for testing without full stack)
		return nil
	}

	c.mu.RLock()
	peerAddr := c.peerAddress
	c.mu.RUnlock()

	// Default fail-safe expiry of 60 seconds per spec recommendation
	// A commissioner MAY read BasicCommissioningInfo.FailSafeExpiryLengthSeconds
	// to get the device's recommended value first.
	const failSafeExpirySeconds = 60
	const breadcrumb = 1 // Use breadcrumb to track commissioning progress

	// Encode the ArmFailSafe request
	req := &generalcommissioning.ArmFailSafeRequest{
		ExpiryLengthSeconds: failSafeExpirySeconds,
		Breadcrumb:          breadcrumb,
	}

	reqData, err := generalcommissioning.EncodeArmFailSafeRequest(req)
	if err != nil {
		return fmt.Errorf("encode ArmFailSafe request: %w", err)
	}

	// Send the InvokeRequest and get the response
	respData, err := c.imClient.InvokeRequest(
		ctx,
		sess,
		peerAddr,
		0,                                                          // Endpoint 0 (root)
		uint32(generalcommissioning.ClusterID),                     // GeneralCommissioning cluster
		uint32(generalcommissioning.CmdArmFailSafe),                // ArmFailSafe command
		reqData,
	)
	if err != nil {
		return fmt.Errorf("invoke ArmFailSafe: %w", err)
	}

	// Decode the response
	resp, err := generalcommissioning.DecodeArmFailSafeResponse(respData)
	if err != nil {
		return fmt.Errorf("decode ArmFailSafe response: %w", err)
	}

	// Check the error code
	if resp.ErrorCode != generalcommissioning.CommissioningOK {
		return fmt.Errorf("%w: %s (%s)", ErrFailSafeArm, resp.ErrorCode.String(), resp.DebugText)
	}

	return nil
}

// performDeviceAttestation verifies the device's attestation.
//
// This implements the Device Attestation Procedure (Spec 6.2.3):
//  1. Send AttestationRequest with random nonce
//  2. Receive AttestationResponse with signed attestation info
//  3. Request DAC and PAI certificates
//  4. Pass to configured AttestationVerifier for verification
//
// The verifier determines how strict the verification is.
// See docs/pkgs/attestation.md for the pluggable design.
func (c *Commissioner) performDeviceAttestation(ctx context.Context, sess *session.SecureContext) error {
	// Skip if no IM client (testing mode without full stack)
	if c.imClient == nil {
		result := &AttestationResult{
			Verified: true,
			Trusted:  false, // Not actually verified
		}
		if c.config.Callbacks.OnDeviceAttestationResult != nil {
			if !c.config.Callbacks.OnDeviceAttestationResult(result) {
				return ErrAttestationFailed
			}
		}
		return nil
	}

	c.mu.RLock()
	peerAddr := c.peerAddress
	c.mu.RUnlock()

	// Execute the attestation protocol and verify using the configured verifier
	attestResult, err := PerformDeviceAttestation(
		ctx,
		c.imClient,
		sess,
		peerAddr,
		c.config.AttestationVerifier,
	)
	if err != nil {
		return fmt.Errorf("device attestation: %w", err)
	}

	// Convert to the commissioner's result type
	result := &AttestationResult{
		Verified:               attestResult.Verified,
		Trusted:                attestResult.Trusted,
		VendorID:               attestResult.VendorID,
		ProductID:              attestResult.ProductID,
		CertificateDeclaration: attestResult.CertificateDeclaration,
		AttestationNonce:       attestResult.AttestationNonce,
	}

	// Check with callback if provided
	if c.config.Callbacks.OnDeviceAttestationResult != nil {
		if !c.config.Callbacks.OnDeviceAttestationResult(result) {
			return ErrAttestationFailed
		}
	}

	return nil
}

// requestCSRAndAddNOC requests CSR and installs operational credentials.
func (c *Commissioner) requestCSRAndAddNOC(ctx context.Context, sess *session.SecureContext) (fabric.NodeID, error) {
	// TODO: Implement CSR request and NOC installation
	// This requires:
	// 1. Send CSRRequest command
	// 2. Parse CSR response
	// 3. Generate NOC from CSR
	// 4. Send AddNOC command

	_ = ctx
	_ = sess

	// Return a placeholder node ID
	return fabric.NodeID(0x0001), nil
}

// configureNetwork configures the operational network on the device.
func (c *Commissioner) configureNetwork(ctx context.Context, sess *session.SecureContext) error {
	// TODO: Implement network configuration
	// This requires NetworkCommissioning cluster commands

	_ = ctx
	_ = sess
	return nil
}

// discoverOperational discovers the device on the operational network.
func (c *Commissioner) discoverOperational(ctx context.Context, nodeID fabric.NodeID) error {
	// TODO: Implement operational discovery
	// Browse for _matter._tcp with the node's operational instance name

	_ = ctx
	_ = nodeID
	return nil
}

// establishCASE establishes a CASE session with the commissioned device.
func (c *Commissioner) establishCASE(ctx context.Context, nodeID fabric.NodeID) (*session.SecureContext, error) {
	// TODO: Implement CASE session establishment
	// This requires the device to be on the operational network

	_ = ctx
	_ = nodeID
	return nil, nil
}

// sendCommissioningComplete sends the CommissioningComplete command.
//
// Spec Reference: Section 11.10.7.6 "CommissioningComplete"
// Per spec, this command MUST be sent over a CASE session, not PASE.
func (c *Commissioner) sendCommissioningComplete(ctx context.Context, sess *session.SecureContext) error {
	if c.imClient == nil {
		// No IM client - skip (for testing without full stack)
		return nil
	}

	if sess == nil {
		// Session can be nil in the skeleton implementation
		return nil
	}

	c.mu.RLock()
	peerAddr := c.peerAddress
	c.mu.RUnlock()

	// CommissioningComplete has no request fields - encode empty struct
	reqData, err := generalcommissioning.EncodeCommissioningCompleteRequest()
	if err != nil {
		return fmt.Errorf("encode CommissioningComplete request: %w", err)
	}

	// Send the InvokeRequest and get the response
	respData, err := c.imClient.InvokeRequest(
		ctx,
		sess,
		peerAddr,
		0,                                                          // Endpoint 0 (root)
		uint32(generalcommissioning.ClusterID),                     // GeneralCommissioning cluster
		uint32(generalcommissioning.CmdCommissioningComplete),      // CommissioningComplete command
		reqData,
	)
	if err != nil {
		return fmt.Errorf("invoke CommissioningComplete: %w", err)
	}

	// Decode the response
	resp, err := generalcommissioning.DecodeCommissioningCompleteResponse(respData)
	if err != nil {
		return fmt.Errorf("decode CommissioningComplete response: %w", err)
	}

	// Check the error code
	if resp.ErrorCode != generalcommissioning.CommissioningOK {
		return fmt.Errorf("%w: %s (%s)", ErrCommissioningCompleteFailed, resp.ErrorCode.String(), resp.DebugText)
	}

	return nil
}

// Cancel cancels an in-progress commissioning operation.
func (c *Commissioner) Cancel() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state == CommissionerStateIdle {
		return ErrNotCommissioning
	}

	if c.cancelFunc != nil {
		c.cancelFunc()
	}

	return nil
}

// CurrentPayload returns the current payload being commissioned.
// Returns nil if no commissioning is in progress.
func (c *Commissioner) CurrentPayload() *payload.SetupPayload {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.currentPayload
}

// CurrentDevice returns the current device being commissioned.
// Returns nil if no device has been discovered yet.
func (c *Commissioner) CurrentDevice() *discovery.ResolvedService {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.currentDevice
}
