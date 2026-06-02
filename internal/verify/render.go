package verify

import (
	"fmt"
	"sort"
	"strings"
)

// renderTestYAML produces a Revyl test YAML document for a flow, matching the
// schema at https://docs.revyl.com/appendix/yaml-test-format. The test name is
// passed in (not Flow.TestName) so it can be made unique per build — a stable
// name across apps gets silently rebound to the first app's build.
func renderTestYAML(f Flow, name, platform, buildName string, vars map[string]string) string {
	var b strings.Builder
	b.WriteString("test:\n")
	b.WriteString("  metadata:\n")
	fmt.Fprintf(&b, "    name: %s\n", yamlStr(name))
	fmt.Fprintf(&b, "    platform: %s\n", platform)
	b.WriteString("    tags:\n")
	b.WriteString("      - greenlight\n")
	b.WriteString("      - runtime\n")
	if len(vars) > 0 {
		b.WriteString("    variables:\n")
		keys := make([]string, 0, len(vars))
		for k := range vars {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "      %s: %s\n", k, yamlStr(vars[k]))
		}
	}
	b.WriteString("  build:\n")
	fmt.Fprintf(&b, "    name: %s\n", yamlStr(buildName))
	b.WriteString("  blocks:\n")
	for _, s := range f.Steps {
		fmt.Fprintf(&b, "    - type: %s\n", s.Type)
		fmt.Fprintf(&b, "      step_description: %s\n", yamlStr(s.Desc))
		if s.Type == "extraction" && s.VariableName != "" {
			fmt.Fprintf(&b, "      variable_name: %s\n", yamlStr(s.VariableName))
		}
	}
	return b.String()
}

// yamlStr returns a safely double-quoted YAML scalar.
func yamlStr(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}
