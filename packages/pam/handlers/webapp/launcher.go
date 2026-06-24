// Package webapp launches and tears down the per-session sandbox browser
// container (the M1 image) that a `webapp` PAM session streams over RDP.
//
// The gateway is the only component that manages this container: it `docker
// run`s the image navigated to the resource's target URL, waits for the
// container-local RDP server to come up, hands the RDP endpoint to the existing
// RDP bridge, and force-removes the container on every session exit path.
// Leaked containers are the top operational hazard, so teardown is deliberately
// redundant (`--rm` on run + an explicit force-remove in Close + a startup
// orphan sweep).
package webapp

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	// defaultSandboxImage is the local dev tag built by
	// cli/packages/pam/handlers/webapp/sandbox/Dockerfile (see M1). Override with
	// a published image via INFISICAL_PAM_WEBAPP_IMAGE.
	defaultSandboxImage = "infisical-pam-webapp-sandbox:dev"
	// containerRDPPort is the port freerdp-shadow-cli listens on inside the image.
	containerRDPPort = "3389"
	// sandboxLabel is stamped on every sandbox container so orphans left by a
	// crashed gateway can be swept on the next startup.
	sandboxLabel = "infisical.pam.webapp"

	readinessTimeout      = 60 * time.Second
	readinessPollInterval = 500 * time.Millisecond
	// dockerCommandTimeout bounds each docker control command (run/port/inspect/rm).
	dockerCommandTimeout = 30 * time.Second
)

// runtimeBinary is the container runtime CLI to shell out to (docker by default;
// override with INFISICAL_PAM_WEBAPP_RUNTIME=podman for an OCI-compatible runtime).
func runtimeBinary() string {
	if v := strings.TrimSpace(os.Getenv("INFISICAL_PAM_WEBAPP_RUNTIME")); v != "" {
		return v
	}
	return "docker"
}

func sandboxImage() string {
	if v := strings.TrimSpace(os.Getenv("INFISICAL_PAM_WEBAPP_IMAGE")); v != "" {
		return v
	}
	return defaultSandboxImage
}

// IsSupported reports whether this gateway can launch webapp sandbox containers:
// the runtime binary is on PATH and its daemon is reachable. Gated into the
// gateway's advertised resource types so a host without a container runtime never
// accepts a webapp session and then fails it at launch.
func IsSupported() bool {
	bin := runtimeBinary()
	if _, err := exec.LookPath(bin); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), dockerCommandTimeout)
	defer cancel()
	// `docker info` succeeds only when the daemon is up and reachable.
	if err := exec.CommandContext(ctx, bin, "info").Run(); err != nil {
		return false
	}
	return true
}

// Sandbox is a running per-session browser container. Host/Port address its
// local RDP server (published to gateway loopback).
type Sandbox struct {
	Host string
	Port uint16

	containerName string
	runtimeBin    string
	closed        bool
}

// containerNameFor derives a deterministic, docker-safe container name from the
// session id so a relaunch (or an orphan sweep) can address the same container.
func containerNameFor(sessionID string) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, sessionID)
	return "infisical-pam-webapp-" + safe
}

// Launch starts a sandbox container navigated to targetURL and blocks until its
// RDP server accepts connections. The caller MUST call Close on the returned
// Sandbox on every exit path.
func Launch(ctx context.Context, sessionID, targetURL string) (*Sandbox, error) {
	bin := runtimeBinary()
	name := containerNameFor(sessionID)
	image := sandboxImage()

	// Clear any orphan from a prior crashed run of THIS session before relaunch
	// (a stale container would hold the deterministic name).
	forceRemove(bin, name)

	runCtx, cancel := context.WithTimeout(ctx, dockerCommandTimeout)
	defer cancel()
	// Publish the container RDP port to an ephemeral loopback host port so the
	// sandbox is reachable only from the gateway process. tini is the image
	// entrypoint (M1) — do NOT pass --init.
	out, err := exec.CommandContext(runCtx, bin, "run", "-d", "--rm",
		"--name", name,
		"--label", sandboxLabel+"=1",
		"--label", sandboxLabel+".session="+sessionID,
		"-e", "TARGET_URL="+targetURL,
		"-p", "127.0.0.1:0:"+containerRDPPort,
		image,
	).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("docker run failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}

	sandbox := &Sandbox{Host: "127.0.0.1", containerName: name, runtimeBin: bin}

	port, err := publishedPort(ctx, bin, name)
	if err != nil {
		sandbox.Close()
		return nil, err
	}
	sandbox.Port = port

	if err := waitForRDP(ctx, bin, name, sandbox.Host, sandbox.Port); err != nil {
		sandbox.Close()
		return nil, err
	}

	log.Info().
		Str("sessionId", sessionID).
		Str("container", name).
		Str("endpoint", fmt.Sprintf("%s:%d", sandbox.Host, sandbox.Port)).
		Str("targetUrl", targetURL).
		Msg("webapp sandbox container ready")
	return sandbox, nil
}

// publishedPort reads the ephemeral host port docker assigned to the container's
// RDP port (`docker port <name> 3389` -> e.g. "127.0.0.1:49153").
func publishedPort(ctx context.Context, bin, name string) (uint16, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, dockerCommandTimeout)
	defer cancel()
	out, err := exec.CommandContext(cmdCtx, bin, "port", name, containerRDPPort).Output()
	if err != nil {
		return 0, fmt.Errorf("docker port lookup failed: %w", err)
	}
	// Output can carry several lines (IPv4 + IPv6); take the first parseable port.
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		_, portStr, splitErr := net.SplitHostPort(line)
		if splitErr != nil {
			continue
		}
		p, convErr := strconv.Atoi(portStr)
		if convErr != nil || p <= 0 || p > 65535 {
			continue
		}
		return uint16(p), nil
	}
	return 0, fmt.Errorf("could not parse published RDP port from %q", strings.TrimSpace(string(out)))
}

// rdpConnectionRequest is a minimal X.224 Connection Request carrying an
// RDP_NEG_REQ that advertises SSL|HYBRID|HYBRID_EX (0x0b). The container's RDP
// server answers it with an X.224 Connection Confirm (a TPKT frame starting
// 0x03). Used purely as a readiness probe.
var rdpConnectionRequest = []byte{
	0x03, 0x00, 0x00, 0x13, // TPKT header, length 19
	0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, // X.224 Connection Request
	0x01, 0x00, 0x08, 0x00, 0x0b, 0x00, 0x00, 0x00, // RDP_NEG_REQ: SSL|HYBRID|HYBRID_EX
}

// waitForRDP blocks until the container's RDP server completes an X.224
// negotiation (CR -> CC), the container exits, or the timeout/context elapses.
//
// A bare TCP dial is NOT sufficient: on macOS Docker Desktop the host-port proxy
// accepts the TCP handshake before the in-container RDP server is listening, so a
// dial succeeds prematurely and the bridge's first real connection (which writes
// a CR) gets reset when the proxy fails to forward it. Probing with an actual CR
// and requiring a CC back proves the RDP server is truly ready to negotiate.
func waitForRDP(ctx context.Context, bin, name, host string, port uint16) error {
	deadline := time.Now().Add(readinessTimeout)
	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("webapp sandbox RDP server not ready after %s", readinessTimeout)
		}
		// Fail fast if the container died during startup (e.g. a bad image).
		if !isRunning(ctx, bin, name) {
			return fmt.Errorf("webapp sandbox container exited before its RDP server became ready")
		}
		if rdpNegotiates(addr, readinessPollInterval) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(readinessPollInterval):
		}
	}
}

// rdpNegotiates reports whether a single X.224 CR -> CC exchange succeeds against
// addr within timeout. A premature proxy-accept fails here: the CR write goes
// through but the forward to the not-yet-listening RDP server is reset, so the
// CC read returns an error.
func rdpNegotiates(addr string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(rdpConnectionRequest); err != nil {
		return false
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return false
	}
	// A valid Connection Confirm is a TPKT frame (version byte 0x03).
	return header[0] == 0x03
}

func isRunning(ctx context.Context, bin, name string) bool {
	cmdCtx, cancel := context.WithTimeout(ctx, dockerCommandTimeout)
	defer cancel()
	out, err := exec.CommandContext(cmdCtx, bin, "inspect", "-f", "{{.State.Running}}", name).Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "true"
}

// Close tears the container down. Idempotent and safe to call on any exit path.
// Uses a background context so teardown still runs when the session context that
// drove the proxy has already been cancelled.
func (s *Sandbox) Close() error {
	if s == nil || s.closed {
		return nil
	}
	s.closed = true
	// Debug knob: leave the container running after the session so its logs can be
	// inspected (the bridge tears down on failure too fast to read them otherwise).
	if strings.TrimSpace(os.Getenv("INFISICAL_PAM_WEBAPP_KEEP")) != "" {
		log.Warn().Str("container", s.containerName).
			Msg("INFISICAL_PAM_WEBAPP_KEEP set — leaving sandbox container running for inspection")
		return nil
	}
	forceRemove(s.runtimeBin, s.containerName)
	return nil
}

func forceRemove(bin, name string) {
	ctx, cancel := context.WithTimeout(context.Background(), dockerCommandTimeout)
	defer cancel()
	// `--rm` removes on stop, but force-remove is the authoritative teardown for a
	// still-running container; "No such container" is the expected no-op.
	if out, err := exec.CommandContext(ctx, bin, "rm", "-f", name).CombinedOutput(); err != nil {
		trimmed := strings.TrimSpace(string(out))
		if !strings.Contains(trimmed, "No such container") {
			log.Warn().Str("container", name).Str("output", trimmed).Err(err).
				Msg("webapp sandbox force-remove failed (possible orphan)")
		}
	}
}

// CleanupOrphans force-removes any sandbox containers left behind by a previous
// gateway process (e.g. a SIGKILL that skipped Close). Best-effort; intended to
// be called once at gateway startup. A no-op when no container runtime is present.
func CleanupOrphans(ctx context.Context) {
	bin := runtimeBinary()
	if _, err := exec.LookPath(bin); err != nil {
		return
	}
	cmdCtx, cancel := context.WithTimeout(ctx, dockerCommandTimeout)
	defer cancel()
	out, err := exec.CommandContext(cmdCtx, bin, "ps", "-aq", "--filter", "label="+sandboxLabel).Output()
	if err != nil {
		return
	}
	ids := strings.Fields(string(out))
	if len(ids) == 0 {
		return
	}
	log.Info().Int("count", len(ids)).Msg("sweeping orphaned webapp sandbox containers")
	for _, id := range ids {
		forceRemove(bin, id)
	}
}
