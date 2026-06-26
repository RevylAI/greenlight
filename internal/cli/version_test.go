package cli

import "testing"

// An ldflags-injected version always wins over the build-info fallback.
func TestResolveVersionPrefersInjected(t *testing.T) {
	old := appVersion
	defer func() { appVersion = old }()

	appVersion = "v1.2.3"
	if got := resolveVersion(); got != "v1.2.3" {
		t.Errorf("resolveVersion() = %q, want v1.2.3", got)
	}
}

// With no injected version, resolveVersion falls back to build info (or "dev")
// but must never return an empty string.
func TestResolveVersionNeverEmpty(t *testing.T) {
	old := appVersion
	defer func() { appVersion = old }()

	for _, v := range []string{"", "dev"} {
		appVersion = v
		if got := resolveVersion(); got == "" {
			t.Errorf("resolveVersion() with appVersion=%q returned empty", v)
		}
	}
}
