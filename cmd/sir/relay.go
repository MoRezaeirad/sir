package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/somoore/sir/pkg/relay"
	"github.com/somoore/sir/pkg/telemetry"
)

// relayEndpointHint renders an example SIR_SLACK_RELAY URL for the listen addr.
// A bind that omits the host (":8787" → all interfaces) keeps the <this-host>
// placeholder; a host-bearing addr (the loopback default) prints a directly
// usable URL instead of the malformed "http://<this-host>127.0.0.1:8787".
func relayEndpointHint(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://" + addr
	}
	if strings.TrimSpace(host) == "" {
		return "http://<this-host>:" + port
	}
	return "http://" + addr
}

// isLoopbackAddr reports whether a listen address binds only the loopback
// interface (so an unauthenticated relay is not reachable off-box).
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return false // e.g. ":8787" binds all interfaces
	}
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// cmdRelay runs the central Slack relay server. Workstations point
// SIR_SLACK_RELAY at this process; it forwards deduplicated, curated alerts to
// one downstream Slack webhook (SIR_SLACK_WEBHOOK), keeping webhook secrets and
// per-event spam off individual machines.
func cmdRelay(args []string) {
	// Default to loopback: the relay is unauthenticated unless SIR_RELAY_TOKEN /
	// SIR_SLACK_SIGNING_SECRET are set, so it must not bind a public interface by
	// accident. An operator who wants fleet ingest passes --addr explicitly
	// (behind a reverse proxy / mTLS, per the docs).
	addr := "127.0.0.1:8787"
	addrExplicit := false
	dedup := 10 * time.Minute
	digest := time.Hour
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--addr":
			if i+1 >= len(args) {
				fatal("--addr requires a value, e.g. :8787")
			}
			addr = args[i+1]
			addrExplicit = true
			i++
		case "--dedup":
			if i+1 >= len(args) {
				fatal("--dedup requires a duration, e.g. 10m")
			}
			d, err := time.ParseDuration(args[i+1])
			if err != nil {
				fatal("parse --dedup: %v", err)
			}
			dedup = d
			i++
		case "--digest":
			if i+1 >= len(args) {
				fatal("--digest requires a duration, e.g. 1h (0 disables)")
			}
			d, err := time.ParseDuration(args[i+1])
			if err != nil {
				fatal("parse --digest: %v", err)
			}
			digest = d
			i++
		default:
			fatal("usage: sir relay [--addr 127.0.0.1:8787] [--dedup 10m] [--digest 1h]\n" +
				"  Auth (recommended): SIR_RELAY_TOKEN (workstation->relay ingest), SIR_SLACK_SIGNING_SECRET (Slack interactions).")
		}
	}

	webhook := strings.TrimSpace(os.Getenv(telemetry.SlackWebhookEnvVar))
	if webhook == "" {
		fatal("sir relay needs a downstream Slack webhook: set %s", telemetry.SlackWebhookEnvVar)
	}
	ingestToken := strings.TrimSpace(os.Getenv(telemetry.SlackRelayTokenEnvVar))
	signingSecret := strings.TrimSpace(os.Getenv(telemetry.SlackSigningSecretEnvVar))
	r, err := relay.New(webhook, relay.Options{
		DedupWindow:        dedup,
		DigestEvery:        digest,
		IngestToken:        ingestToken,
		SlackSigningSecret: signingSecret,
		Logger:             log.New(os.Stderr, "sir-relay ", log.LstdFlags|log.LUTC),
	})
	if err != nil {
		fatal("%v", err)
	}

	// Loud, actionable warnings: the relay is a network surface, so make any
	// missing control explicit rather than silently running open.
	if ingestToken == "" {
		fmt.Fprintf(os.Stderr, "sir relay WARNING: %s not set — /v1/detections and /stats are UNAUTHENTICATED. Set it on the relay and on each workstation to require a shared secret.\n", telemetry.SlackRelayTokenEnvVar)
	}
	if signingSecret == "" {
		fmt.Fprintf(os.Stderr, "sir relay WARNING: %s not set — /slack/interactions signatures are NOT verified. Set your Slack app signing secret to reject forged interactions.\n", telemetry.SlackSigningSecretEnvVar)
	}
	if addrExplicit && !isLoopbackAddr(addr) && (ingestToken == "" || signingSecret == "") {
		fmt.Fprintln(os.Stderr, "sir relay WARNING: binding a non-loopback address without full authentication. Do not expose the relay directly to the internet — front it with a reverse proxy / mTLS and set the secrets above.")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go r.Run(ctx)

	srv := &http.Server{
		Addr:              addr,
		Handler:           r.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	authState := "token+signature enforced"
	switch {
	case ingestToken == "" && signingSecret == "":
		authState = "UNAUTHENTICATED (set SIR_RELAY_TOKEN + SIR_SLACK_SIGNING_SECRET)"
	case ingestToken == "":
		authState = "ingest unauthenticated (set SIR_RELAY_TOKEN)"
	case signingSecret == "":
		authState = "Slack signatures unverified (set SIR_SLACK_SIGNING_SECRET)"
	}
	fmt.Printf("sir relay listening on %s (dedup=%s, digest=%s, auth: %s)\n", addr, dedup, digest, authState)
	fmt.Printf("  workstations: export SIR_SLACK_RELAY=%s/v1/detections\n", relayEndpointHint(addr))
	if !addrExplicit {
		fmt.Println("  bound to loopback by default; pass --addr to expose (behind a reverse proxy / mTLS, never directly).")
	}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fatal("relay server: %v", err)
	}
}
