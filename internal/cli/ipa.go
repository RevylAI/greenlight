package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/RevylAI/greenlight/internal/ipa"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	ipaFormat string
	ipaOutput string
)

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
	ipaCmd.Flags().StringVar(&ipaOutput, "output", "", "write report to file (stdout if omitted)")
	rootCmd.AddCommand(ipaCmd)
}

func runIPA(cmd *cobra.Command, args []string) error {
	ipaPath := args[0]

	if _, err := os.Stat(ipaPath); os.IsNotExist(err) {
		return fmt.Errorf("IPA file not found: %s", ipaPath)
	}

	format := strings.ToLower(ipaFormat)
	if format != "json" {
		purple.Println("\n  greenlight ipa — inspect your binary before submission.")
		fmt.Printf("  IPA: %s\n\n", ipaPath)
	}

	start := time.Now()
	result, err := ipa.Inspect(ipaPath)
	if err != nil {
		return fmt.Errorf("inspection failed: %w", err)
	}
	elapsed := time.Since(start)

	var output *os.File
	if ipaOutput != "" {
		output, err = os.Create(ipaOutput)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer output.Close()
	} else {
		output = os.Stdout
	}

	switch format {
	case "json":
		return writeIPAJSON(output, result, elapsed)
	default:
		return writeIPATerminal(output, result, elapsed)
	}
}

func writeIPATerminal(w *os.File, result *ipa.InspectResult, elapsed time.Duration) error {
	if result.AppName != "" {
		fmt.Fprintf(w, "  App:  %s\n", result.AppName)
	}
	sizeMB := float64(result.Size) / (1024 * 1024)
	fmt.Fprintf(w, "  Size: %.1fMB\n\n", sizeMB)

	if len(result.Findings) == 0 {
		color.New(color.FgGreen, color.Bold).Fprintln(w, "  No issues found!")
		fmt.Fprintln(w)
		printIPAFooter(w, 0, 0, 0, elapsed)
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
		red.Fprintln(w, "  CRITICAL — Will be rejected")
		fmt.Fprintln(w)
		for _, f := range criticals {
			red.Fprint(w, "  [CRITICAL] ")
			if f.Guideline != "" {
				bold.Fprintf(w, "§%s ", f.Guideline)
			}
			bold.Fprintln(w, f.Title)
			fmt.Fprintf(w, "             %s\n", f.Detail)
			if f.Fix != "" {
				green.Fprint(w, "             Fix: ")
				fmt.Fprintln(w, f.Fix)
			}
			fmt.Fprintln(w)
		}
	}

	if len(warns) > 0 {
		yellow.Fprintln(w, "  WARNING — High rejection risk")
		fmt.Fprintln(w)
		for _, f := range warns {
			yellow.Fprint(w, "  [WARN]     ")
			if f.Guideline != "" {
				bold.Fprintf(w, "§%s ", f.Guideline)
			}
			bold.Fprintln(w, f.Title)
			fmt.Fprintf(w, "             %s\n", f.Detail)
			if f.Fix != "" {
				green.Fprint(w, "             Fix: ")
				fmt.Fprintln(w, f.Fix)
			}
			fmt.Fprintln(w)
		}
	}

	if len(infos) > 0 {
		dim.Fprintln(w, "  INFO — Best practices")
		fmt.Fprintln(w)
		for _, f := range infos {
			dim.Fprint(w, "  [INFO]     ")
			if f.Guideline != "" {
				bold.Fprintf(w, "§%s ", f.Guideline)
			}
			bold.Fprintln(w, f.Title)
			fmt.Fprintf(w, "             %s\n", f.Detail)
			if f.Fix != "" {
				green.Fprint(w, "             Fix: ")
				fmt.Fprintln(w, f.Fix)
			}
			fmt.Fprintln(w)
		}
	}

	printIPAFooter(w, len(criticals), len(warns), len(infos), elapsed)
	return nil
}

func printIPAFooter(w *os.File, criticals, warns, infos int, elapsed time.Duration) {
	red := color.New(color.FgRed, color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	total := criticals + warns + infos

	dim.Fprintln(w, "  ─────────────────────────────────────────────")
	fmt.Fprintln(w)

	if criticals == 0 {
		green.Fprint(w, "  GREENLIT")
		fmt.Fprint(w, " — no critical issues in binary")
	} else {
		red.Fprint(w, "  NOT READY")
		fmt.Fprintf(w, " — %d critical issue(s) must be fixed", criticals)
	}
	fmt.Fprintln(w)

	if total > 0 {
		fmt.Fprintf(w, "  %d findings: ", total)
		if criticals > 0 {
			red.Fprintf(w, "%d critical  ", criticals)
		}
		if warns > 0 {
			color.New(color.FgYellow).Fprintf(w, "%d warn  ", warns)
		}
		if infos > 0 {
			dim.Fprintf(w, "%d info", infos)
		}
		fmt.Fprintln(w)
	}

	dim.Fprintf(w, "  completed in %s\n", elapsed.Round(time.Millisecond))

	fmt.Fprintln(w)
	dim.Fprintln(w, "  ─────────────────────────────────────────────")
	fmt.Fprint(w, "  Built by ")
	purple.Fprint(w, "Revyl")
	fmt.Fprintln(w, " — the mobile reliability platform")
	dim.Fprintln(w, "  Catch more than rejections. Catch bugs.")
	fmt.Fprint(w, "  ")
	color.New(color.Underline).Fprintln(w, "https://revyl.com")
	fmt.Fprintln(w)

	return
}

func writeIPAJSON(w *os.File, result *ipa.InspectResult, elapsed time.Duration) error {
	// Derive summary counts for JSON consumers (mirrors preflight/codescan summary).
	var criticals, warns, infos int
	for _, f := range result.Findings {
		switch f.Severity {
		case "CRITICAL":
			criticals++
		case "WARN":
			warns++
		case "INFO":
			infos++
		}
	}
	payload := struct {
		IPAPath  string       `json:"ipa_path"`
		AppName  string       `json:"app_name"`
		BundleID string       `json:"bundle_id,omitempty"`
		Size     int64        `json:"size_bytes"`
		Findings []ipa.Finding `json:"findings"`
		Summary  struct {
			Total    int  `json:"total"`
			Critical int  `json:"critical"`
			Warns    int  `json:"warns"`
			Infos    int  `json:"infos"`
			Passed   bool `json:"passed"`
		} `json:"summary"`
		Elapsed string `json:"elapsed"`
	}{
		IPAPath:  result.IPAPath,
		AppName:  result.AppName,
		BundleID: result.BundleID,
		Size:     result.Size,
		Findings: result.Findings,
		Elapsed:  elapsed.Round(time.Millisecond).String(),
	}
	// Ensure empty findings encodes as [] not null.
	if payload.Findings == nil {
		payload.Findings = []ipa.Finding{}
	}
	payload.Summary.Total = len(result.Findings)
	payload.Summary.Critical = criticals
	payload.Summary.Warns = warns
	payload.Summary.Infos = infos
	payload.Summary.Passed = criticals == 0

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}
