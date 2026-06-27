package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/RevylAI/greenlight/internal/privacy"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var privacyCmd = &cobra.Command{
	Use:   "privacy [path]",
	Short: "Validate privacy manifest and Required Reason API compliance",
	Long: `Deep privacy compliance scan for your project.

Checks:
  • PrivacyInfo.xcprivacy exists and is properly configured
  • Required Reason APIs detected in code vs declared in manifest
    - File timestamps (NSFileManager dates)
    - System boot time (ProcessInfo.systemUptime)
    - Disk space (volumeAvailableCapacity)
    - Active keyboards (activeInputModes)
    - User Defaults (NSUserDefaults, AsyncStorage)
  • Tracking SDKs detected vs ATT implementation
  • NSPrivacyTracking, NSPrivacyAccessedAPITypes declarations

No App Store Connect account needed — runs entirely offline.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runPrivacy,
}

func init() {
	rootCmd.AddCommand(privacyCmd)
}

func runPrivacy(cmd *cobra.Command, args []string) error {
	path := "."
	if len(args) > 0 {
		path = args[0]
	}

	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cannot access path: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("path must be a directory: %s", path)
	}

	purple.Println("\n  greenlight privacy — validate your privacy compliance.")
	fmt.Printf("  Scanning: %s\n\n", path)

	start := time.Now()
	result, err := privacy.Scan(path)
	if err != nil {
		return fmt.Errorf("privacy scan failed: %w", err)
	}
	elapsed := time.Since(start)

	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow)
	green := color.New(color.FgGreen)
	bold := color.New(color.Bold)

	// Status summary
	if result.HasPrivacyInfo {
		green.Fprint(os.Stdout, "  ✓ ")
		fmt.Println("PrivacyInfo.xcprivacy found")
	} else {
		red.Fprint(os.Stdout, "  ✗ ")
		fmt.Println("PrivacyInfo.xcprivacy NOT found")
	}

	if len(result.DetectedAPIs) > 0 {
		fmt.Printf("  Required Reason APIs detected: %s\n", strings.Join(result.DetectedAPIs, ", "))
	}

	if len(result.DeclaredAPIs) > 0 {
		fmt.Printf("  APIs declared in manifest:     %s\n", strings.Join(result.DeclaredAPIs, ", "))
	}

	if len(result.TrackingSDKs) > 0 {
		yellow.Fprint(os.Stdout, "  Tracking SDKs found: ")
		fmt.Println(strings.Join(result.TrackingSDKs, ", "))
	}

	fmt.Println()

	if len(result.Findings) == 0 {
		green.Fprintln(os.Stdout, "  No privacy issues found!")
		fmt.Println()
		printPrivacyFooter(0, 0, 0, elapsed)
		return nil
	}

	// Group findings
	var criticals, warns, infos []privacy.Finding
	for _, f := range result.Findings {
		switch f.Severity {
		case "CRITICAL":
			criticals = append(criticals, f)
		case "WARN":
			warns = append(warns, f)
		case "INFO":
			infos = append(infos, f)
		}
	}

	if len(criticals) > 0 {
		red.Println("  CRITICAL — Will be rejected")
		fmt.Println()
		for _, f := range criticals {
			red.Fprint(os.Stdout, "  [CRITICAL] ")
			if f.Guideline != "" {
				bold.Fprintf(os.Stdout, "§%s ", f.Guideline)
			}
			bold.Fprintln(os.Stdout, f.Title)
			fmt.Printf("             %s\n", f.Detail)
			if f.Fix != "" {
				green.Fprint(os.Stdout, "             Fix: ")
				fmt.Println(f.Fix)
			}
			fmt.Println()
		}
	}

	if len(warns) > 0 {
		yellow.Println("  WARNING — High rejection risk")
		fmt.Println()
		for _, f := range warns {
			yellow.Fprint(os.Stdout, "  [WARN]     ")
			if f.Guideline != "" {
				bold.Fprintf(os.Stdout, "§%s ", f.Guideline)
			}
			bold.Fprintln(os.Stdout, f.Title)
			fmt.Printf("             %s\n", f.Detail)
			if f.Fix != "" {
				green.Fprint(os.Stdout, "             Fix: ")
				fmt.Println(f.Fix)
			}
			fmt.Println()
		}
	}

	if len(infos) > 0 {
		dim.Println("  INFO — Best practices")
		fmt.Println()
		for _, f := range infos {
			dim.Fprint(os.Stdout, "  [INFO]     ")
			bold.Fprintln(os.Stdout, f.Title)
			fmt.Printf("             %s\n", f.Detail)
			if f.Fix != "" {
				green.Fprint(os.Stdout, "             Fix: ")
				fmt.Println(f.Fix)
			}
			fmt.Println()
		}
	}

	printPrivacyFooter(len(criticals), len(warns), len(infos), elapsed)
	return nil
}

func printPrivacyFooter(criticals, warns, infos int, elapsed time.Duration) {
	red := color.New(color.FgRed, color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	total := criticals + warns + infos

	dim.Fprintln(os.Stdout, "  ─────────────────────────────────────────────")
	fmt.Println()

	if criticals == 0 {
		green.Fprint(os.Stdout, "  GREENLIT")
		fmt.Fprint(os.Stdout, " — privacy compliance looks good")
	} else {
		red.Fprint(os.Stdout, "  NOT READY")
		fmt.Fprintf(os.Stdout, " — %d critical privacy issue(s)", criticals)
	}
	fmt.Println()

	if total > 0 {
		fmt.Fprintf(os.Stdout, "  %d findings: ", total)
		if criticals > 0 {
			red.Fprintf(os.Stdout, "%d critical  ", criticals)
		}
		if warns > 0 {
			color.New(color.FgYellow).Fprintf(os.Stdout, "%d warn  ", warns)
		}
		if infos > 0 {
			dim.Fprintf(os.Stdout, "%d info", infos)
		}
		fmt.Println()
	}

	dim.Fprintf(os.Stdout, "  completed in %s\n", elapsed.Round(time.Millisecond))

	fmt.Println()
	dim.Fprintln(os.Stdout, "  ─────────────────────────────────────────────")
	fmt.Fprint(os.Stdout, "  Built by ")
	purple.Fprint(os.Stdout, "Revyl")
	fmt.Fprintln(os.Stdout, " — the mobile reliability platform")
	dim.Fprintln(os.Stdout, "  Catch more than rejections. Catch bugs.")
	fmt.Fprint(os.Stdout, "  ")
	color.New(color.Underline).Fprintln(os.Stdout, "https://revyl.com")
	fmt.Println()
}
