package cli

import (
	"errors"
	"testing"

	"github.com/RevylAI/greenlight/internal/preflight"
	"github.com/RevylAI/greenlight/internal/verify"
)

// preflightExit only trips when --exit-code is set, and then on any CRITICAL or
// HIGH static finding, or a failed/errored runtime flow.
func TestPreflightExit(t *testing.T) {
	defer func() { preflightExitCode = false }()

	crit := &preflight.Result{Summary: preflight.Summary{Critical: 1}}
	high := &preflight.Result{Summary: preflight.Summary{High: 1}}
	clean := &preflight.Result{Summary: preflight.Summary{Warns: 3}}

	// Without the flag: never errors, whatever the findings.
	preflightExitCode = false
	for _, r := range []*preflight.Result{crit, high, clean} {
		if err := preflightExit(r, nil); err != nil {
			t.Errorf("no --exit-code: expected nil, got %v", err)
		}
	}

	// With the flag: critical and high trip; clean static does not.
	preflightExitCode = true
	if !errors.Is(preflightExit(crit, nil), ErrThreshold) {
		t.Error("critical should trip --exit-code")
	}
	if !errors.Is(preflightExit(high, nil), ErrThreshold) {
		t.Error("high should trip --exit-code")
	}
	if err := preflightExit(clean, nil); err != nil {
		t.Errorf("clean static should not trip, got %v", err)
	}

	// A failed runtime flow trips even when static is clean; a passed one does not.
	if !errors.Is(preflightExit(clean, &verify.Result{Summary: verify.Summary{Failed: 1}}), ErrThreshold) {
		t.Error("failed flow should trip --exit-code")
	}
	if err := preflightExit(clean, &verify.Result{Summary: verify.Summary{Passed: true}}); err != nil {
		t.Errorf("clean static + passed runtime should not trip, got %v", err)
	}
}
