package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/RevylAI/greenlight/internal/ipa"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var ipaFormat string

var ipaCmd = &cobra.Command{
	Use:   "ipa <path-to-ipa>",
	Short: "Inspect an IPA binary for App Store compliance issues",
	Long: `Inspect an IPA file for common issues that cause App Store rejection.

Checks:
  • PrivacyInfo.xcprivacy exists and is populated
  • Info.plist completeness (required keys, purpose strings)
  • App Transport Security configuration
  • App icon presence and sizes
  • Launch storyboard presence
  • App size vs cellular download limit
  • Embedded framework privacy manifests
  • Purpose string quality (empty, vague)

No App Store Connect account needed — works entirely offline.`,
	Args: cobra.ExactArgs(1),
	RunE: runIPA,
}

func init() {
	ipaCmd.Flags().StringVar(&ipaFormat, "format", "terminal", "output format: terminal, json")
	rootCmd.AddCommand(ipaCmd)
}

func runIPA(cmd *cobra.Command, args []string) error {
	ipaPath := args[0]

	if _, err := os.Stat(ipaPath); os.IsNotExist(err) {
		return fmt.Errorf("IPA file not found: %s", ipaPath)
	}

	purple.Println("\n  greenlight ipa — inspect your binary before submission.")
	fmt.Printf("  IPA: %s\n\n", ipaPath)

	start := time.Now()
	result, err := ipa.Inspect(ipaPath)
	if err != nil {
		return fmt.Errorf("inspection failed: %w", err)
	}
	elapsed := time.Since(start)

	if result.AppName != "" {
		fmt.Printf("  App:  %s\n", result.AppName)
	}
	sizeMB := float64(result.Size) / (1024 * 1024)
	fmt.Printf("  Size: %.1fMB\n\n", sizeMB)

	if len(result.Findings) == 0 {
		color.New(color.FgGreen, color.Bold).Fprintln(os.Stdout, "  No issues found!")
		fmt.Println()
		printIPAFooter(0, 0, 0, elapsed)
		return nil
	}

	// Group findings
	var criticals, warns, infos []ipa.Finding
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

	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow)
	green := color.New(color.FgGreen)
	bold := color.New(color.Bold)

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

	printIPAFooter(len(criticals), len(warns), len(infos), elapsed)
	return nil
}

func printIPAFooter(criticals, warns, infos int, elapsed time.Duration) {
	red := color.New(color.FgRed, color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	total := criticals + warns + infos

	dim.Fprintln(os.Stdout, "  ─────────────────────────────────────────────")
	fmt.Println()

	if criticals == 0 {
		green.Fprint(os.Stdout, "  GREENLIT")
		fmt.Fprint(os.Stdout, " — no critical issues in binary")
	} else {
		red.Fprint(os.Stdout, "  NOT READY")
		fmt.Fprintf(os.Stdout, " — %d critical issue(s) must be fixed", criticals)
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

	return
}
