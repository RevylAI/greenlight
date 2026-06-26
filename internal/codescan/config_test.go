package codescan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigAbsent(t *testing.T) {
	cfg, err := LoadConfig(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if cfg != nil {
		t.Errorf("expected nil config when no file is present, got %+v", cfg)
	}
}

func TestLoadConfigValidation(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) {
		if err := os.WriteFile(filepath.Join(dir, ".greenlight.yml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write("rules:\n  not-a-real-rule:\n    enabled: false\n")
	if _, err := LoadConfig(dir); err == nil {
		t.Error("expected an error for an unknown rule id")
	}

	write("rules:\n  hardcoded-ipv4:\n    severity: bogus\n")
	if _, err := LoadConfig(dir); err == nil {
		t.Error("expected an error for an invalid severity")
	}

	// Severity override on a non-PatternRule (PlistKeyRule) can't be honored.
	write("rules:\n  missing-privacy-keys:\n    severity: info\n")
	if _, err := LoadConfig(dir); err == nil {
		t.Error("expected an error for a severity override on a non-PatternRule")
	}

	// A typo'd field is rejected (KnownFields), not silently ignored.
	write("rules:\n  hardcoded-ipv4:\n    enable: false\n") // 'enable', not 'enabled'
	if _, err := LoadConfig(dir); err == nil {
		t.Error("expected an error for an unknown field (typo)")
	}

	write("rules:\n  hardcoded-ipv4:\n    severity: info\nignore:\n  - vendor\n")
	cfg, err := LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil || cfg.Rules["hardcoded-ipv4"].Severity != "info" || len(cfg.Ignore) != 1 {
		t.Errorf("unexpected config: %+v", cfg)
	}
}

func TestApplyRulesDisableAndOverride(t *testing.T) {
	disabled := false
	cfg := &Config{Rules: map[string]RuleConfig{
		"hardcoded-ipv4":     {Enabled: &disabled},
		"platform-reference": {Severity: "info"},
	}}

	for _, r := range cfg.applyRules(AllRules()) {
		if ruleIDOf(r) == "hardcoded-ipv4" {
			t.Error("hardcoded-ipv4 should have been disabled (removed)")
		}
		if pr, ok := r.(*PatternRule); ok && pr.id == "platform-reference" && pr.severity != SeverityInfo {
			t.Errorf("platform-reference severity = %v, want INFO", pr.severity)
		}
	}
}

func TestIgnores(t *testing.T) {
	cfg := &Config{Ignore: []string{"vendor", "*.generated.ts", "src/legacy"}}

	for _, p := range []string{"vendor/Foo.swift", "vendor/deep/Bar.swift", "api.generated.ts", "src/legacy/Old.ts", "src/legacy"} {
		if !cfg.ignores(p) {
			t.Errorf("expected %q to be ignored", p)
		}
	}
	for _, p := range []string{"src/App.tsx", "lib/vendored.ts", "x.generated.ts.bak"} {
		if cfg.ignores(p) {
			t.Errorf("expected %q NOT to be ignored", p)
		}
	}
}
