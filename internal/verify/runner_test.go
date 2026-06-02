package verify

import (
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
