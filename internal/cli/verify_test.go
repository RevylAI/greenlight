package cli

import "testing"

// parseVars must split on the first '=' so credential values containing commas
// or '=' (base64/JWT padding) survive intact — unlike pflag's StringToString.
func TestParseVars(t *testing.T) {
	m := parseVars([]string{"email=a,b@acme.com", "password=p@ss==w0rd", "noeq", "=noval"})
	if m["email"] != "a,b@acme.com" {
		t.Errorf("email = %q, want a,b@acme.com", m["email"])
	}
	if m["password"] != "p@ss==w0rd" {
		t.Errorf("password = %q, want p@ss==w0rd", m["password"])
	}
	if _, ok := m["noeq"]; ok {
		t.Errorf("entry without '=' should be skipped")
	}
	if len(m) != 2 {
		t.Errorf("expected 2 entries, got %d: %v", len(m), m)
	}
	if parseVars(nil) != nil {
		t.Errorf("nil input should return nil map")
	}
}

func TestValidateFlows(t *testing.T) {
	if err := validateFlows(nil); err != nil {
		t.Errorf("nil flows should be valid: %v", err)
	}
	if err := validateFlows([]string{"account-deletion", "sign-in-apple"}); err != nil {
		t.Errorf("known flows should be valid: %v", err)
	}
	if err := validateFlows([]string{"account-deletion", "nope"}); err == nil {
		t.Errorf("unknown flow should error")
	}
}
