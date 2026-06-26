package cli

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	appVersion string
	verbose    bool
)

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
	// Enables `greenlight --version` (cobra auto-adds the flag when set).
	rootCmd.Version = resolveVersion()
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	// Match the `version` subcommand's wording ("greenlight <v>") for `--version`.
	rootCmd.SetVersionTemplate("greenlight {{.Version}}\n")

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(authCmd)
	rootCmd.AddCommand(guidelinesCmd)
	rootCmd.AddCommand(versionCmd)
}
