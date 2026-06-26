package codescan

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the optional .greenlight.yml that tunes the code scan: disable rules,
// override a rule's severity, or ignore file paths. It applies to the code scan
// only (the rule engine); the privacy/ipa/metadata scanners are unaffected.
type Config struct {
	Rules  map[string]RuleConfig `yaml:"rules"`
	Ignore []string              `yaml:"ignore"`
}

// RuleConfig overrides a single rule by id.
type RuleConfig struct {
	Enabled  *bool  `yaml:"enabled"`  // nil = default (enabled); false disables the rule
	Severity string `yaml:"severity"` // "" = default; otherwise info|warn|critical
}

// configNames are the filenames LoadConfig looks for in the project root.
var configNames = []string{".greenlight.yml", ".greenlight.yaml"}

// LoadConfig reads .greenlight.yml/.greenlight.yaml from root. It returns
// (nil, nil) when no config file exists, and validates rule severities/ids.
func LoadConfig(root string) (*Config, error) {
	for _, name := range configNames {
		p := filepath.Join(root, name)
		data, err := os.ReadFile(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		cfg, err := decodeConfig(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if err := cfg.validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		return cfg, nil
	}
	return nil, nil
}

// LoadConfigFile reads an explicit config path (for a --config flag).
func LoadConfigFile(p string) (*Config, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	cfg, err := decodeConfig(data)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// decodeConfig parses YAML with KnownFields(true) so a typo'd key (e.g. `rule:`
// instead of `rules:`) errors instead of being silently dropped. An empty file
// decodes to an empty Config.
func decodeConfig(data []byte) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return &cfg, nil // empty / comments-only file
		}
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	rulesByID := map[string]Rule{}
	for _, r := range AllRules() {
		if id := ruleIDOf(r); id != "" {
			rulesByID[id] = r
		}
	}
	for id, rc := range c.Rules {
		r, ok := rulesByID[id]
		if !ok {
			return fmt.Errorf("unknown rule id %q (run 'greenlight codescan' to see rule ids in the output, or check the docs)", id)
		}
		if rc.Severity != "" {
			if _, ok := parseSeverity(rc.Severity); !ok {
				return fmt.Errorf("rule %q: invalid severity %q (use info, warn, or critical)", id, rc.Severity)
			}
			// Only PatternRule carries a single configurable severity; the others
			// emit per-finding severities, so an override there would be a no-op.
			if _, ok := r.(*PatternRule); !ok {
				return fmt.Errorf("rule %q doesn't support a severity override; use enabled: true/false instead", id)
			}
		}
	}
	return nil
}

func parseSeverity(s string) (Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":
		return SeverityInfo, true
	case "warn", "warning":
		return SeverityWarn, true
	case "critical":
		return SeverityCritical, true
	}
	return 0, false
}

// ruleIDOf returns a rule's id across the concrete rule types.
func ruleIDOf(r Rule) string {
	switch v := r.(type) {
	case *PatternRule:
		return v.id
	case *PlistKeyRule:
		return v.id
	case *ExpoConfigRule:
		return v.id
	}
	return ""
}

// apply filters/overrides a rule set per config and returns the kept rules.
func (c *Config) applyRules(rules []Rule) []Rule {
	if c == nil || len(c.Rules) == 0 {
		return rules
	}
	out := rules[:0]
	for _, r := range rules {
		rc, ok := c.Rules[ruleIDOf(r)]
		if !ok {
			out = append(out, r)
			continue
		}
		if rc.Enabled != nil && !*rc.Enabled {
			continue // disabled
		}
		if rc.Severity != "" {
			// Severity override applies to PatternRule; other rule types carry
			// per-finding severities and are left as-is.
			if pr, ok := r.(*PatternRule); ok {
				if sev, ok := parseSeverity(rc.Severity); ok {
					pr.severity = sev
				}
			}
		}
		out = append(out, r)
	}
	return out
}

// ignores reports whether a relative path matches any ignore glob. It supports
// exact globs (path.Match), basename globs like "*.generated.ts", bare directory
// or segment names ("vendor"), and path prefixes ("src/legacy").
func (c *Config) ignores(relPath string) bool {
	if c == nil {
		return false
	}
	rel := filepath.ToSlash(relPath)
	base := path.Base(rel)
	for _, g := range c.Ignore {
		g = filepath.ToSlash(strings.TrimSpace(g))
		if g == "" {
			continue
		}
		if ok, _ := path.Match(g, rel); ok {
			return true
		}
		if !strings.Contains(g, "/") {
			if ok, _ := path.Match(g, base); ok {
				return true
			}
			for _, seg := range strings.Split(rel, "/") {
				if seg == g {
					return true
				}
			}
		}
		prefix := strings.TrimSuffix(g, "/")
		if rel == prefix || strings.HasPrefix(rel, prefix+"/") {
			return true
		}
	}
	return false
}
