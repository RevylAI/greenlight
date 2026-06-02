package verify

import (
	"fmt"
	"strings"
)

// renderTestYAML produces a Revyl test YAML document for a flow, matching the
// schema at https://docs.revyl.com/appendix/yaml-test-format. The test name is
// passed in (not Flow.TestName) so it can be made unique per build — a stable
// name across apps gets silently rebound to the first app's build.
//
// Credential values are inlined directly into step text rather than emitted as a
// `variables:` block: Revyl treats metadata.variables as launch-time values, and
// for apps that don't expect them the app fails to launch (the run records zero
// steps). Inlining keeps the launch clean and the steps self-contained.
func renderTestYAML(f Flow, name, platform, buildName string, vars map[string]string) string {
	var b strings.Builder
	b.WriteString("test:\n")
	b.WriteString("  metadata:\n")
	fmt.Fprintf(&b, "    name: %s\n", yamlStr(name))
	fmt.Fprintf(&b, "    platform: %s\n", yamlStr(platform))
	b.WriteString("    tags:\n")
	b.WriteString("      - greenlight\n")
	b.WriteString("      - runtime\n")
	b.WriteString("  build:\n")
	fmt.Fprintf(&b, "    name: %s\n", yamlStr(buildName))
	b.WriteString("  blocks:\n")
	for _, s := range f.Steps {
		fmt.Fprintf(&b, "    - type: %s\n", s.Type)
		fmt.Fprintf(&b, "      step_description: %s\n", yamlStr(substituteVars(s.Desc, vars)))
		if s.Type == "extraction" && s.VariableName != "" {
			fmt.Fprintf(&b, "      variable_name: %s\n", yamlStr(s.VariableName))
		}
	}
	return b.String()
}

// substituteVars replaces {{key}} placeholders with their provided values.
// Unprovided placeholders are left as-is.
func substituteVars(s string, vars map[string]string) string {
	for k, v := range vars {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}
	return s
}

// yamlStr returns a safely double-quoted YAML scalar. Backslashes are escaped
// first, then quotes, then control characters are converted to their escape
// sequences (a raw newline/tab/CR would otherwise terminate or corrupt the scalar).
func yamlStr(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	s = strings.ReplaceAll(s, "\t", `\t`)
	return `"` + s + `"`
}
