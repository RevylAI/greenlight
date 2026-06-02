package revyl

import "testing"

// sampleFailedReport is a trimmed slice of a real `revyl test report --json`
// response (captured from a live device run), exercising the exact field names
// the parser depends on.
const sampleFailedReport = `{
  "app_name": "Spootify",
  "device_model": "iPhone 17 Pro Max",
  "os_version": "iOS 26.2",
  "session_status": "failed",
  "success": false,
  "total_steps": 1,
  "failed_steps": 1,
  "passed_steps": 0,
  "execution_id": "b990b41a-f777-4239-8701-65535e3cf565",
  "report_url": "https://app.revyl.ai/tests/report?taskId=b990b41a-f777-4239-8701-65535e3cf565",
  "steps": [
    {
      "execution_order": 0,
      "status": "failed",
      "effective_status": "failed",
      "step_description": "Go to the login screen",
      "status_reason": "Step execution failed: Failed to open URL spotify://login: Failed to open URL spotify://login on simulator",
      "step_type": "instruction"
    }
  ]
}`

const samplePassedReport = `{
  "session_status": "passed",
  "success": true,
  "total_steps": 1,
  "passed_steps": 1,
  "report_url": "https://app.revyl.ai/tests/report?taskId=abc",
  "steps": [
    {"execution_order": 0, "status": "passed", "step_description": "Go to the login screen"}
  ]
}`

// sampleSetupFailure is the real amazoon case: the run "failed" but executed
// ZERO steps (build failed to install/launch). This must NOT read as a broken
// flow — the runner reclassifies a 0-step failure as a setup error.
const sampleSetupFailure = `{
  "app_name": "amazoon",
  "device_model": "iPhone 17 Pro Max",
  "os_version": "iOS 26.2",
  "session_status": "failed",
  "success": false,
  "total_steps": 0,
  "failed_steps": 0,
  "passed_steps": 0,
  "report_url": "https://app.revyl.ai/tests/report?taskId=1a04ac9e-894e-48f2-8ef3-54692700feb4",
  "steps": []
}`

func TestParseReportFailed(t *testing.T) {
	r, err := parseReport(sampleFailedReport)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.Decided || r.Passed {
		t.Errorf("expected a decided failure, got Decided=%v Passed=%v", r.Decided, r.Passed)
	}
	if r.FailedStep != "Go to the login screen" {
		t.Errorf("FailedStep = %q, want %q", r.FailedStep, "Go to the login screen")
	}
	if r.FailedReason == "" || len(r.FailedReason) > 180 {
		t.Errorf("FailedReason not extracted/cleaned: %q", r.FailedReason)
	}
	// cleanReason strips the "Step execution failed: " prefix.
	if want := "Failed to open URL"; r.FailedReason[:len(want)] != want {
		t.Errorf("FailedReason = %q, want it to start with %q", r.FailedReason, want)
	}
	if r.ReportURL == "" {
		t.Errorf("ReportURL not extracted")
	}
	if r.StepsRun != 1 {
		t.Errorf("StepsRun = %d, want 1", r.StepsRun)
	}
	if r.DeviceModel != "iPhone 17 Pro Max" || r.OSVersion != "iOS 26.2" {
		t.Errorf("device context not extracted: %q / %q", r.DeviceModel, r.OSVersion)
	}
}

// TestParseReportSetupFailure pins the amazoon regression: a failed run that
// executed zero steps is a setup/launch failure, distinguishable via StepsRun==0.
func TestParseReportSetupFailure(t *testing.T) {
	r, err := parseReport(sampleSetupFailure)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.Decided || r.Passed {
		t.Errorf("expected a decided failure, got Decided=%v Passed=%v", r.Decided, r.Passed)
	}
	if r.StepsRun != 0 {
		t.Errorf("StepsRun = %d, want 0 (the runner uses this to flag a setup failure, not a broken flow)", r.StepsRun)
	}
}

func TestParseReportPassed(t *testing.T) {
	r, err := parseReport(samplePassedReport)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.Decided || !r.Passed {
		t.Errorf("expected a decided pass, got Decided=%v Passed=%v", r.Decided, r.Passed)
	}
	if r.FailedStep != "" {
		t.Errorf("expected no failed step on a pass, got %q", r.FailedStep)
	}
}

func TestVerdictAndStepFromRunJSON(t *testing.T) {
	// Exit-code is the backstop, but explicit JSON verdicts should win when present.
	pass := true
	if v, decided := (runJSON{Passed: &pass}).verdict(); !decided || !v {
		t.Errorf("explicit passed=true not honored: v=%v decided=%v", v, decided)
	}
	if v, decided := (runJSON{Status: "failed"}).verdict(); !decided || v {
		t.Errorf("status=failed not honored: v=%v decided=%v", v, decided)
	}
	if _, decided := (runJSON{}).verdict(); decided {
		t.Errorf("empty runJSON should be undecided (fall back to exit code)")
	}
}
