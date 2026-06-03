package verify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// redactVars must scrub sensitive --var values (passwords/tokens) from reported
// strings while leaving non-sensitive ones (email) intact.
func TestRedactVars(t *testing.T) {
	vars := map[string]string{
		"email":    "qa@acme.com",
		"password": "hunter2",
		"apiToken": "tok_abc123",
	}
	in := "Log in with qa@acme.com and hunter2 (token tok_abc123) failed"
	got := redactVars(in, vars)

	if strings.Contains(got, "hunter2") {
		t.Errorf("password leaked: %q", got)
	}
	if strings.Contains(got, "tok_abc123") {
		t.Errorf("token leaked: %q", got)
	}
	if !strings.Contains(got, "qa@acme.com") {
		t.Errorf("non-sensitive email should remain: %q", got)
	}
	if !strings.Contains(got, "[redacted]") {
		t.Errorf("expected a redaction marker: %q", got)
	}
}

// ValidateArtifact must accept a simulator .app (directory) and an .apk (file),
// reject a device .ipa with simulator guidance, and reject other/missing paths.
func TestValidateArtifact(t *testing.T) {
	dir := t.TempDir()

	appBundle := filepath.Join(dir, "Demo.app") // .app is a directory bundle
	if err := os.Mkdir(appBundle, 0o755); err != nil {
		t.Fatal(err)
	}
	apk := filepath.Join(dir, "demo.apk") // .apk is a file
	if err := os.WriteFile(apk, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	ipa := filepath.Join(dir, "demo.ipa")
	if err := os.WriteFile(ipa, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	appAsFile := filepath.Join(dir, "Bad.app") // .app that is wrongly a file
	if err := os.WriteFile(appAsFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	zip := filepath.Join(dir, "demo.zip") // exists, but unsupported extension
	if err := os.WriteFile(zip, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := ValidateArtifact("", "ios"); err != nil {
		t.Errorf("empty path should be valid (no upload requested): %v", err)
	}
	if err := ValidateArtifact(appBundle, "ios"); err != nil {
		t.Errorf("a .app directory should be valid for ios: %v", err)
	}
	if err := ValidateArtifact(apk, "android"); err != nil {
		t.Errorf("an .apk file should be valid for android: %v", err)
	}
	if err := ValidateArtifact(ipa, "ios"); err == nil || !strings.Contains(err.Error(), "simulator") {
		t.Errorf("a .ipa should be rejected with simulator guidance, got: %v", err)
	}
	if err := ValidateArtifact(appAsFile, "ios"); err == nil {
		t.Errorf("a .app that is a plain file should be rejected")
	}
	if err := ValidateArtifact(filepath.Join(dir, "nope.app"), "ios"); err == nil {
		t.Errorf("a missing artifact should be rejected")
	}
	if err := ValidateArtifact(zip, "ios"); err == nil {
		t.Errorf("an unsupported extension should be rejected")
	}
	// Platform/extension mismatches must be caught early, not mid-upload.
	if err := ValidateArtifact(apk, "ios"); err == nil {
		t.Errorf("an .apk on platform ios should be rejected")
	}
	if err := ValidateArtifact(appBundle, "android"); err == nil {
		t.Errorf("a .app on platform android should be rejected")
	}
}
