package cli

import (
	"fmt"
	"runtime/debug"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the greenlight version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("greenlight %s\n", resolveVersion())
	},
}

// resolveVersion prefers the ldflags-injected version (release builds), then
// falls back to the module version embedded by the Go toolchain so that
// `go install ...@latest` / `@v1.2.3` reports a real version instead of "dev".
func resolveVersion() string {
	if appVersion != "" && appVersion != "dev" {
		return appVersion
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	if appVersion != "" {
		return appVersion
	}
	return "dev"
}
