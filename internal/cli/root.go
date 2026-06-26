package cli

import (
	"errors"
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	appVersion string
	verbose    bool
)

// ErrThreshold is returned by scan commands when --exit-code is set and the
// findings cross the failure threshold. main() maps it to a non-zero exit status
// without printing anything — the report is already the user-facing output.
var ErrThreshold = errors.New("findings exceeded --exit-code threshold")

var purple = color.New(color.FgHiMagenta)
var dim = color.New(color.Faint)

var rootCmd = &cobra.Command{
	Use:   "greenlight",
	Short: "Pre-submission compliance scanner for the Apple App Store",
	Long: fmt.Sprintf(`%s

Greenlight scans your app against Apple's App Store Review Guidelines
before you submit, catching rejection risks so you ship with confidence.

Get started:
  greenlight preflight .          Run ALL checks — one command, zero uploads
  greenlight preflight . --ipa X  Include IPA binary analysis
  greenlight scan --app-id ID     Check App Store Connect metadata (needs API key)
  greenlight guidelines search    Browse Apple's review guidelines`,
		purple.Sprint("greenlight — know before you submit.")),
}

func SetVersion(v string) {
	appVersion = v
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Errors are printed by main() (so --exit-code's sentinel can exit quietly);
	// usage on a runtime error is just noise.
	rootCmd.SilenceErrors = true
	rootCmd.SilenceUsage = true

	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(authCmd)
	rootCmd.AddCommand(guidelinesCmd)
	rootCmd.AddCommand(versionCmd)
}
