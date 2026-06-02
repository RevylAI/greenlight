package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/RevylAI/greenlight/internal/revyl"
	"github.com/RevylAI/greenlight/internal/verify"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	verifyBuildName   string
	verifyFlows       []string
	verifyVars        map[string]string
	verifyDeviceModel string
	verifyOSVersion   string
	verifyPlatform    string
	verifyBuild       bool
	verifyDryRun      bool
	verifyFormat      string
	verifyOutput      string
	verifyRevylBin    string
	verifyTimeout     int
)

var verifyCmd = &cobra.Command{
	Use:   "verify [path]",
	Short: "Validate flow-dependent guidelines on a cloud device via Revyl",
	Long: `Runtime tier. Static checks confirm a flow EXISTS in source; verify confirms
it WORKS on a cloud device by handing flow-dependent guidelines to the Revyl CLI.

This catches what static analysis structurally cannot: a 'Delete Account' button
wired to nothing passes codescan — the string 'deleteAccount' is present, so §5.1.1
is suppressed — but it dead-ends at runtime, and Apple rejects it. verify runs the
flow on a device and catches it.

Flows verified: account-deletion (§5.1.1), restore-purchases (§3.1.1),
sign-in-apple (§4.8). Only flows your app actually claims are run.

Unlike every other greenlight command this is NOT offline: it needs the revyl CLI,
a Revyl account (revyl auth login), and a registered build. Run preflight first;
run verify before you submit.

Usage:
  greenlight verify . --dry-run                                   # show the tests it would run, no device
  greenlight verify . --build-name "My App" --var email=qa@acme.com --var password=secret
  greenlight verify . --build-name "My App" --flows account-deletion --os-version "iOS 26.2"`,
	Args: cobra.MaximumNArgs(1),
	RunE: runVerify,
}

func init() {
	verifyCmd.Flags().StringVar(&verifyBuildName, "build-name", "", "Revyl registered build/app name (required to run; maps to YAML build.name)")
	verifyCmd.Flags().StringSliceVar(&verifyFlows, "flows", nil, "limit to specific flows: account-deletion, restore-purchases, sign-in-apple")
	verifyCmd.Flags().StringToStringVar(&verifyVars, "var", nil, "test variable, e.g. --var email=qa@acme.com (repeatable)")
	verifyCmd.Flags().StringVar(&verifyDeviceModel, "device-model", "", "target device model, e.g. \"iPhone 16\"")
	verifyCmd.Flags().StringVar(&verifyOSVersion, "os-version", "", "target OS version, e.g. \"iOS 26.2\"")
	verifyCmd.Flags().StringVar(&verifyPlatform, "platform", "ios", "platform: ios or android")
	verifyCmd.Flags().BoolVar(&verifyBuild, "build", false, "build and upload via revyl before running")
	verifyCmd.Flags().BoolVar(&verifyDryRun, "dry-run", false, "generate the tests but do not execute on a device")
	verifyCmd.Flags().StringVar(&verifyFormat, "format", "terminal", "output format: terminal, json")
	verifyCmd.Flags().StringVar(&verifyOutput, "output", "", "write report to file (stdout if omitted)")
	verifyCmd.Flags().StringVar(&verifyRevylBin, "revyl", "", "path to the revyl binary (default: auto-detect)")
	verifyCmd.Flags().IntVar(&verifyTimeout, "timeout", 0, "per-flow timeout in seconds (0 = revyl default)")
	rootCmd.AddCommand(verifyCmd)
}

func runVerify(cmd *cobra.Command, args []string) error {
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

	purple.Println("\n  greenlight verify — does the flow actually work, on a cloud device?")
	fmt.Printf("  Project: %s\n", path)
	if verifyBuildName != "" {
		fmt.Printf("  Build:   %s\n", verifyBuildName)
	}
	if verifyDryRun {
		dim.Println("  Mode:    dry-run (no device)")
	}
	fmt.Println()

	start := time.Now()
	result, err := verify.Run(verify.Config{
		ProjectPath: path,
		BuildName:   verifyBuildName,
		Platform:    verifyPlatform,
		Flows:       verifyFlows,
		Vars:        verifyVars,
		DeviceModel: verifyDeviceModel,
		OSVersion:   verifyOSVersion,
		Build:       verifyBuild,
		Timeout:     time.Duration(verifyTimeout) * time.Second,
		DryRun:      verifyDryRun,
		RevylBin:    verifyRevylBin,
	})
	if err != nil {
		return fmt.Errorf("verify failed: %w", err)
	}
	result.Elapsed = time.Since(start)

	out := os.Stdout
	if verifyOutput != "" {
		out, err = os.Create(verifyOutput)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer out.Close()
	}

	if strings.ToLower(verifyFormat) == "json" {
		return writeVerifyJSON(out, result)
	}
	writeVerifyTerminal(out, result)
	return nil
}

func writeVerifyTerminal(w *os.File, r *verify.Result) {
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow)
	greenC := color.New(color.FgGreen)
	bold := color.New(color.Bold)

	var claimed []string
	if r.Claims.AccountCreation {
		claimed = append(claimed, "account creation")
	}
	if r.Claims.IAP {
		claimed = append(claimed, "in-app purchases")
	}
	if r.Claims.SocialLogin {
		claimed = append(claimed, "social login")
	}
	if len(claimed) > 0 {
		fmt.Fprintf(w, "  Flow-dependent features detected: %s\n\n", strings.Join(claimed, ", "))
	} else {
		dim.Fprintln(w, "  No flow-dependent features detected in source.")
		fmt.Fprintln(w)
	}

	for _, f := range r.Flows {
		switch f.Status {
		case verify.StatusFailed:
			red.Fprint(w, "  [FAILED]   ")
			bold.Fprintf(w, "§%s %s\n", f.Guideline, f.Title)
			if f.FailedStep != "" {
				dim.Fprintf(w, "             failed at: %s\n", f.FailedStep)
			}
			if f.FailedReason != "" {
				dim.Fprintf(w, "             reason: %s\n", f.FailedReason)
			}
			fmt.Fprintf(w, "             %s\n", f.Detail)
			if f.ReportURL != "" {
				fmt.Fprint(w, "             report: ")
				color.New(color.Underline).Fprintln(w, f.ReportURL)
			}
			fmt.Fprintln(w)
		case verify.StatusVerified:
			greenC.Fprint(w, "  [VERIFIED] ")
			bold.Fprintf(w, "§%s %s\n", f.Guideline, f.Title)
			dim.Fprintln(w, "             ran on-device and behaved correctly")
			fmt.Fprintln(w)
		case verify.StatusError:
			yellow.Fprint(w, "  [SETUP]    ")
			bold.Fprintf(w, "§%s %s\n", f.Guideline, f.Title)
			fmt.Fprintf(w, "             could not run: %s\n", f.Detail)
			fmt.Fprintln(w)
		case verify.StatusPending:
			yellow.Fprint(w, "  [pending]  ")
			bold.Fprintf(w, "§%s %s\n", f.Guideline, f.Title)
			dim.Fprintln(w, "             claimed in your code — validate it on a cloud device with Revyl")
			fmt.Fprintln(w)
		case verify.StatusSkipped:
			dim.Fprintf(w, "  [skipped]  §%s %s — %s\n", f.Guideline, f.Title, f.Detail)
		}
	}

	if r.DryRun {
		fmt.Fprintln(w)
		for _, f := range r.Flows {
			if f.YAML == "" {
				continue
			}
			dim.Fprintf(w, "  ── generated Revyl test: %s ──\n", f.ID)
			for _, line := range strings.Split(strings.TrimRight(f.YAML, "\n"), "\n") {
				fmt.Fprintf(w, "  %s\n", line)
			}
			fmt.Fprintln(w)
		}
	}

	if r.Onboarding != nil {
		printSignupCTA(w, r)
		return
	}
	printVerifyFooter(w, r)
}

// printSignupCTA is the greenlight -> Revyl activation funnel: when a user
// reaches the runtime tier without a Revyl account, show them exactly what
// they'd unlock and how to sign up — instead of a raw auth error.
func printSignupCTA(w *os.File, r *verify.Result) {
	bold := color.New(color.Bold)
	greenC := color.New(color.FgGreen)

	dim.Fprintln(w, "  ─────────────────────────────────────────────")
	fmt.Fprintln(w)

	n := r.Summary.Pending
	bold.Fprintf(w, "  %d flow(s) Apple will test that static analysis can't confirm.\n", n)
	fmt.Fprint(w, "  Validate them on cloud devices with ")
	purple.Fprint(w, "Revyl")
	fmt.Fprintln(w, " — free to start.")
	fmt.Fprintln(w)

	switch r.Onboarding.Reason {
	case verify.OnboardNotAuthenticated:
		fmt.Fprintln(w, "  You have the Revyl CLI — you're one step away:")
		fmt.Fprintln(w)
		fmt.Fprint(w, "    Sign up free   ")
		color.New(color.Underline).Fprintln(w, revyl.SignupURL)
		fmt.Fprint(w, "    Then run       ")
		greenC.Fprintln(w, revyl.LoginCmd)
		dim.Fprintln(w, "    (already have an account? just run that)")
	default: // OnboardCLIMissing
		fmt.Fprintln(w, "  Three steps to your first runtime check:")
		fmt.Fprintln(w)
		fmt.Fprint(w, "    1. Sign up free    ")
		color.New(color.Underline).Fprintln(w, revyl.SignupURL)
		fmt.Fprint(w, "    2. Install the CLI ")
		greenC.Fprintln(w, revyl.InstallCmd)
		fmt.Fprint(w, "    3. Authenticate    ")
		greenC.Fprintln(w, revyl.LoginCmd)
	}

	fmt.Fprintln(w)
	fmt.Fprint(w, "  Then re-run:  ")
	greenC.Fprintln(w, "greenlight verify . --build-name \"<your Revyl build>\"")

	fmt.Fprintln(w)
	dim.Fprintln(w, "  ─────────────────────────────────────────────")
	fmt.Fprint(w, "  Powered by ")
	purple.Fprint(w, "Revyl")
	fmt.Fprintln(w, " — the mobile reliability platform")
	dim.Fprintln(w, "  Static catches rejections. Revyl catches broken flows.")
	fmt.Fprintln(w)
}

func printVerifyFooter(w *os.File, r *verify.Result) {
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow)
	green := color.New(color.FgGreen, color.Bold)
	s := r.Summary

	dim.Fprintln(w, "  ─────────────────────────────────────────────")
	fmt.Fprintln(w)

	switch {
	case r.DryRun:
		n := 0
		for _, f := range r.Flows {
			if f.YAML != "" {
				n++
			}
		}
		dim.Fprintf(w, "  dry-run — %d flow(s) would be verified on-device\n", n)
	case s.Failed > 0:
		red.Fprint(w, "  NOT READY")
		fmt.Fprintf(w, " — %d flow(s) passed static analysis but FAILED on-device\n", s.Failed)
	case s.Errored > 0 && s.Verified == 0:
		yellow.Fprint(w, "  COULD NOT VERIFY")
		fmt.Fprintf(w, " — %d flow(s) could not run (see setup notes above)\n", s.Errored)
	case s.Verified > 0:
		green.Fprint(w, "  VERIFIED")
		fmt.Fprintf(w, " — %d flow(s) confirmed working on a cloud device", s.Verified)
		if s.Errored > 0 {
			fmt.Fprintf(w, ", %d could not run", s.Errored)
		}
		fmt.Fprintln(w)
	default:
		dim.Fprintln(w, "  nothing to verify")
	}

	if s.Total > 0 {
		fmt.Fprintf(w, "  %d flow(s): ", s.Total)
		if s.Failed > 0 {
			red.Fprintf(w, "%d failed  ", s.Failed)
		}
		if s.Verified > 0 {
			color.New(color.FgGreen).Fprintf(w, "%d verified  ", s.Verified)
		}
		if s.Errored > 0 {
			yellow.Fprintf(w, "%d setup  ", s.Errored)
		}
		fmt.Fprintln(w)
	}

	dim.Fprintf(w, "  completed in %s\n", r.Elapsed.Round(time.Millisecond))

	fmt.Fprintln(w)
	dim.Fprintln(w, "  ─────────────────────────────────────────────")
	fmt.Fprint(w, "  Powered by ")
	purple.Fprint(w, "Revyl")
	fmt.Fprintln(w, " — the mobile reliability platform")
	dim.Fprintln(w, "  Static catches rejections. Revyl catches broken flows.")
	fmt.Fprint(w, "  ")
	color.New(color.Underline).Fprintln(w, "https://revyl.com")
	fmt.Fprintln(w)
}

func verifyJSONObject(r *verify.Result) interface{} {
	return struct {
		ProjectPath string              `json:"project_path"`
		BuildName   string              `json:"build_name,omitempty"`
		Claims      interface{}         `json:"claims"`
		Flows       []verify.FlowResult `json:"flows"`
		Summary     verify.Summary      `json:"summary"`
		DryRun      bool                `json:"dry_run"`
		Elapsed     string              `json:"elapsed"`
	}{
		ProjectPath: r.ProjectPath,
		BuildName:   r.BuildName,
		Claims:      r.Claims,
		Flows:       r.Flows,
		Summary:     r.Summary,
		DryRun:      r.DryRun,
		Elapsed:     r.Elapsed.Round(time.Millisecond).String(),
	}
}

func writeVerifyJSON(w *os.File, r *verify.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(verifyJSONObject(r))
}
