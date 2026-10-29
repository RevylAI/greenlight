package cli

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/RevylAI/greenlight/internal/privacy"
)

// `greenlight privacy --format json` used to fail with "unknown flag: --format"
// (upstream issue #31): runPrivacy had no --format flag at all, unlike every
// sibling scan command (preflight, codescan, playscan, ipa, scan, verify).
// This runs the real command path end-to-end and asserts stdout is valid,
// parseable JSON rather than the human-readable report.
func TestPrivacyFormatJSON(t *testing.T) {
	oldFormat := privacyFormat
	defer func() { privacyFormat = oldFormat }()
	privacyFormat = "json"

	dir := t.TempDir()
	if err := os.WriteFile(dir+"/app.ts", []byte("const x = 1;\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	runErr := runPrivacy(privacyCmd, []string{dir})

	w.Close()
	os.Stdout = oldStdout

	if runErr != nil {
		t.Fatalf("runPrivacy: %v", runErr)
	}

	var result privacy.ScanResult
	if err := json.NewDecoder(r).Decode(&result); err != nil {
		t.Fatalf("stdout was not valid JSON: %v", err)
	}
	if result.ProjectPath != dir {
		t.Errorf("ProjectPath = %q, want %q", result.ProjectPath, dir)
	}
}

// The default (and any unrecognized) --format must still produce the
// human-readable terminal report, matching every other scan command's
// "silently fall back to terminal" convention.
func TestPrivacyFormatDefaultsToTerminal(t *testing.T) {
	oldFormat := privacyFormat
	defer func() { privacyFormat = oldFormat }()
	privacyFormat = "terminal"

	dir := t.TempDir()

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	runErr := runPrivacy(privacyCmd, []string{dir})

	w.Close()
	os.Stdout = oldStdout

	if runErr != nil {
		t.Fatalf("runPrivacy: %v", runErr)
	}

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	out := string(buf[:n])

	var discard privacy.ScanResult
	if err := json.Unmarshal([]byte(out), &discard); err == nil {
		t.Fatalf("expected human-readable output for terminal format, got valid JSON: %s", out)
	}
	if out == "" {
		t.Fatal("expected non-empty terminal report")
	}
}
