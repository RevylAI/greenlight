package cli

import (
	"errors"
	"os"
	"path/filepath"
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
	// A crashed scanner surfaces only as WARN, but the scan is incomplete.
	incomplete := &preflight.Result{Summary: preflight.Summary{Warns: 1}, Incomplete: true}

	// Without the flag: never errors, whatever the findings.
	preflightExitCode = false
	for _, r := range []*preflight.Result{crit, high, clean, incomplete} {
		if err := preflightExit(r, nil); err != nil {
			t.Errorf("no --exit-code: expected nil, got %v", err)
		}
	}

	// With the flag: critical, high, and an incomplete scan trip; clean does not.
	preflightExitCode = true
	if !errors.Is(preflightExit(crit, nil), ErrThreshold) {
		t.Error("critical should trip --exit-code")
	}
	if !errors.Is(preflightExit(high, nil), ErrThreshold) {
		t.Error("high should trip --exit-code")
	}
	if !errors.Is(preflightExit(incomplete, nil), ErrThreshold) {
		t.Error("an incomplete scan (crashed scanner) should trip --exit-code")
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

// --- review regression: runtime tier platform ---------------------------

// preflight --verify used to hardcode Platform: "ios", so an Android-only
// project had its flows run against the wrong store and its .apk rejected.
func TestVerifyPlatformFollowsProject(t *testing.T) {
	androidOnly := t.TempDir()
	if err := os.MkdirAll(filepath.Join(androidOnly, "app", "src", "main"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(androidOnly, "app", "src", "main", "AndroidManifest.xml"),
		[]byte(`<manifest package="com.example"><application/></manifest>`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(androidOnly, "app", "build.gradle"),
		[]byte("android { defaultConfig { targetSdk 36 } }"), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := verifyPlatformFor(androidOnly, ""); got != "android" {
		t.Errorf("android-only project: platform = %q, want android", got)
	}

	// An explicit artifact extension wins over project detection: the file
	// itself is unambiguous about what it is.
	if got := verifyPlatformFor(androidOnly, "build/MyApp.app"); got != "ios" {
		t.Errorf("explicit .app: platform = %q, want ios", got)
	}
	if got := verifyPlatformFor(t.TempDir(), "build/app-release.apk"); got != "android" {
		t.Errorf("explicit .apk: platform = %q, want android", got)
	}

	// An empty or iOS project keeps the previous default.
	if got := verifyPlatformFor(t.TempDir(), ""); got != "ios" {
		t.Errorf("unrecognised project: platform = %q, want ios", got)
	}
}
