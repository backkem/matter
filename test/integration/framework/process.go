// Package framework provides test infrastructure for Matter integration tests.
package framework

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// DeviceProcess manages the lifecycle of a Matter device binary for testing.
type DeviceProcess struct {
	binaryPath string
	port       int
	args       []string
	logFile    string

	cmd        *exec.Cmd
	started    bool
	mu         sync.Mutex
	stdout     *logWriter
	stderr     *logWriter
	logFileHandle *os.File
	done       chan struct{}
	ctx        context.Context
	cancelFunc context.CancelFunc
}

// DeviceProcessConfig holds configuration for a device process.
type DeviceProcessConfig struct {
	// BinaryPath is the path to the device binary (e.g., "cmd/matter-light-device")
	BinaryPath string

	// Port is the UDP port to listen on (default: 5540)
	Port int

	// Discriminator is the 12-bit discriminator value (default: 3840)
	Discriminator uint16

	// Passcode is the 27-bit setup PIN code (default: 20202021)
	Passcode uint32

	// StoragePath is the directory for persistent storage (default: temp dir)
	StoragePath string

	// LogFile is an optional path to write logs to (in addition to test output)
	LogFile string

	// ExtraArgs are additional command-line arguments
	ExtraArgs []string
}

// NewDeviceProcess creates a new device process manager.
func NewDeviceProcess(config DeviceProcessConfig) *DeviceProcess {
	if config.Port == 0 {
		config.Port = 5540
	}
	if config.Discriminator == 0 {
		config.Discriminator = 3840
	}
	if config.Passcode == 0 {
		config.Passcode = 20202021
	}

	args := []string{
		"-port", strconv.Itoa(config.Port),
		"-discriminator", strconv.FormatUint(uint64(config.Discriminator), 10),
		"-passcode", strconv.FormatUint(uint64(config.Passcode), 10),
	}

	if config.StoragePath != "" {
		args = append(args, "-storage", config.StoragePath)
	}

	args = append(args, config.ExtraArgs...)

	ctx, cancel := context.WithCancel(context.Background())

	return &DeviceProcess{
		binaryPath: config.BinaryPath,
		port:       config.Port,
		args:       args,
		logFile:    config.LogFile,
		done:       make(chan struct{}),
		ctx:        ctx,
		cancelFunc: cancel,
	}
}

// Start starts the device binary using `go run`.
func (d *DeviceProcess) Start() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.started {
		return fmt.Errorf("device process already started")
	}

	// Get absolute path to the package
	absPath, err := filepath.Abs(d.binaryPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Determine binary name for logging
	binaryName := filepath.Base(d.binaryPath)

	// Build command args: go run . [device args...]
	cmdArgs := []string{"run", "."}
	cmdArgs = append(cmdArgs, d.args...)

	// Create command using `go run`
	d.cmd = exec.CommandContext(d.ctx, "go", cmdArgs...)
	d.cmd.Dir = absPath

	// Enable full PION logging for debugging
	d.cmd.Env = append(os.Environ(),
		"PION_LOG_TRACE=all",
		"PION_LOG_DEBUG=all",
		"PION_LOG_INFO=all",
		"PION_LOG_WARN=all",
		"PION_LOG_ERROR=all",
	)

	// Open log file if specified
	if d.logFile != "" {
		logFile, err := os.OpenFile(d.logFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return fmt.Errorf("failed to open log file: %w", err)
		}
		d.logFileHandle = logFile
	}

	// Set up logging
	d.stdout = newLogWriter(fmt.Sprintf("[%s stdout]", binaryName), d.logFileHandle)
	d.stderr = newLogWriter(fmt.Sprintf("[%s stderr]", binaryName), d.logFileHandle)
	d.cmd.Stdout = d.stdout
	d.cmd.Stderr = d.stderr

	// Start the process
	if err := d.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start device: %w", err)
	}

	d.started = true

	// Monitor process in background
	go func() {
		defer close(d.done)
		d.cmd.Wait()
	}()

	// Give the device time to start up and begin advertising
	time.Sleep(2 * time.Second)

	return nil
}

// Stop gracefully stops the device process.
func (d *DeviceProcess) Stop() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.started {
		return nil
	}

	// Cancel context
	d.cancelFunc()

	// Send SIGTERM
	if d.cmd != nil && d.cmd.Process != nil {
		if err := d.cmd.Process.Signal(syscall.SIGTERM); err != nil {
			// If SIGTERM fails, try SIGKILL
			d.cmd.Process.Kill()
		}
	}

	// Wait for process to exit (with timeout)
	select {
	case <-d.done:
		// Process exited cleanly
	case <-time.After(5 * time.Second):
		// Force kill
		if d.cmd != nil && d.cmd.Process != nil {
			d.cmd.Process.Kill()
		}
	}

	// Close log file if open
	if d.logFileHandle != nil {
		d.logFileHandle.Close()
		d.logFileHandle = nil
	}

	d.started = false
	return nil
}

// Port returns the UDP port the device is listening on.
func (d *DeviceProcess) Port() int {
	return d.port
}

// OnboardingPayload returns the manual pairing code for the device.
// This is a simple implementation that only supports the default setup.
// For QR codes, you'd need to generate them based on discriminator/passcode.
func (d *DeviceProcess) OnboardingPayload() string {
	// For now, return the manual pairing code
	// TODO: Generate proper QR code payload
	return "34970112332" // This is a placeholder - needs proper generation
}

// IsRunning returns true if the device process is currently running.
func (d *DeviceProcess) IsRunning() bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.started {
		return false
	}

	// Check if process is still alive
	select {
	case <-d.done:
		return false
	default:
		return true
	}
}

// logWriter is a simple io.Writer that prefixes each line with a label.
// It writes to stdout and optionally to a file.
type logWriter struct {
	prefix  string
	logFile *os.File
	mu      sync.Mutex
}

func newLogWriter(prefix string, logFile *os.File) *logWriter {
	return &logWriter{
		prefix:  prefix,
		logFile: logFile,
	}
}

func (w *logWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Log with prefix to stdout
	fmt.Printf("%s %s", w.prefix, string(p))

	// Also write to log file if specified
	if w.logFile != nil {
		fmt.Fprintf(w.logFile, "%s %s", w.prefix, string(p))
	}

	return len(p), nil
}
