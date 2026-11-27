package main

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"strings"
	"time"
)

// Diagnoses the central app asks for in the pull: the same read-only report as
// `scanner-guard-agent diagnose IP`, sent back to <url>/diagnostics. The
// central app only sends an IP and a capture length, never a command.

const (
	maxRemoteCapture = 120 * time.Second
	maxReport        = 64 << 10
)

// startDiagnosis runs r in the background, once per id: the central app keeps
// listing a request until its report arrives.
func (a *Agent) startDiagnosis(ctx context.Context, r DiagnosisRequest) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.diagnoses[r.ID] {
		return
	}
	// ponytail: ids are never forgotten; a few bytes each, one per request made in the panel.
	a.diagnoses[r.ID] = true
	go a.runDiagnosis(ctx, r)
}

func (a *Agent) runDiagnosis(ctx context.Context, r DiagnosisRequest) {
	var b strings.Builder
	ip, err := netip.ParseAddr(r.IP)
	switch {
	case a.cfg.Central.Diagnose != nil && !*a.cfg.Central.Diagnose:
		b.WriteString("Diagnoses from the central app are off on this server (central.diagnose: false in agent.yaml).\n")
	case err != nil:
		fmt.Fprintf(&b, "%q is not an IP address.\n", r.IP)
	default:
		capture := min(max(time.Duration(r.Capture)*time.Second, 0), maxRemoteCapture)
		log.Printf("diagnosis #%d of %s asked by the central app (capture %s)", r.ID, ip, capture)
		a.diagnose.Lock()
		diagnose(&b, ip, a.cfg.path, "24h", capture, a.exec)
		a.diagnose.Unlock()
	}

	if err := a.central.Diagnosis(ctx, r.ID, truncate(b.String(), maxReport)); err != nil {
		log.Printf("diagnosis #%d to central: %v", r.ID, err)
		a.mu.Lock()
		delete(a.diagnoses, r.ID) // run again when the central app lists it again
		a.mu.Unlock()
	}
}
