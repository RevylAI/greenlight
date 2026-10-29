package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/RevylAI/greenlight/internal/asc"
	"github.com/RevylAI/greenlight/internal/checks"
	"github.com/RevylAI/greenlight/internal/config"
	"github.com/RevylAI/greenlight/internal/report"
	"github.com/spf13/cobra"
)

var (
	scanAppID    string
	scanBuildNum string
	scanFormat   string
	scanOutput   string
	scanTier     int
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run pre-submission checks against your app",
	Long: `Scan your app against Apple's App Store Review Guidelines.

Checks are organized into tiers:
  --tier 1   Metadata & completeness (API-based, fast)
  --tier 2   AI content analysis (requires API key)
  --tier 3   Binary inspection (requires IPA path)
  --tier 4   Historical pattern matching (community data)

By default, runs all tiers.`,
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringVar(&scanAppID, "app-id", "", "App Store Connect app ID (required)")
	scanCmd.Flags().StringVar(&scanBuildNum, "build", "", "build number to check (latest if omitted)")
	scanCmd.Flags().StringVar(&scanFormat, "format", "terminal", "output format: terminal, json, junit")
	scanCmd.Flags().StringVar(&scanOutput, "output", "", "write report to file (stdout if omitted)")
	scanCmd.Flags().IntVar(&scanTier, "tier", 4, "max check tier to run (1-4)")
	scanCmd.MarkFlagRequired("app-id")
}

func runScan(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("not authenticated — run 'greenlight auth setup' first: %w", err)
	}

	// 'scan' talks to the App Store Connect v1 REST API, which only an API
	// key (generateToken) can authenticate to. 'auth login' saves an Apple ID
	// web session instead — real credentials, but the wrong shape for this
	// client. Without this check, cfg.KeyID/IssuerID/PrivateKeyPath are empty
	// and asc.NewClient fails deep inside generateToken with a confusing
	// "failed to read private key: open : no such file or directory".
	if !cfg.IsValid() {
		return fmt.Errorf("not authenticated — run 'greenlight auth setup' first")
	}
	if cfg.AuthMethod != config.AuthMethodAPIKey {
		return fmt.Errorf("'scan' needs an App Store Connect API key; the Apple ID session from 'auth login' can't call the v1 API — run 'greenlight auth setup' instead")
	}

	// Banner
	purple.Println("\n  greenlight — know before you submit.")
	fmt.Printf("  App ID:   %s\n", scanAppID)
	fmt.Printf("  Tier:     1-%d\n", scanTier)
	fmt.Printf("  Format:   %s\n\n", scanFormat)

	// Init API client
	client, err := asc.NewClient(cfg.KeyID, cfg.IssuerID, cfg.PrivateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	// Run checks
	start := time.Now()
	runner := checks.NewRunner(client, verbose)
	results, err := runner.Run(cmd.Context(), scanAppID, scanBuildNum, scanTier)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}
	elapsed := time.Since(start)

	// Generate report
	rep := report.New(results, elapsed)

	var output *os.File
	if scanOutput != "" {
		output, err = os.Create(scanOutput)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer output.Close()
	} else {
		output = os.Stdout
	}

	switch strings.ToLower(scanFormat) {
	case "json":
		return rep.WriteJSON(output)
	case "junit":
		return rep.WriteJUnit(output)
	default:
		return rep.WriteTerminal(output)
	}
}
