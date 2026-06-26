package preflight

import "testing"

// HIGH findings are counted separately, but Passed stays "no criticals" so a
// HIGH-only result is still passed=true (the headline shows NEEDS REVIEW).
func TestComputeSummaryCountsHigh(t *testing.T) {
	s := computeSummary([]Finding{
		{Severity: "CRITICAL"},
		{Severity: "HIGH"},
		{Severity: "HIGH"},
		{Severity: "WARN"},
		{Severity: "INFO"},
	})
	if s.Total != 5 || s.Critical != 1 || s.High != 2 || s.Warns != 1 || s.Infos != 1 {
		t.Errorf("counts wrong: %+v", s)
	}
	if s.Passed {
		t.Error("expected Passed=false with a critical present")
	}
	if h := computeSummary([]Finding{{Severity: "HIGH"}}); !h.Passed {
		t.Error("expected Passed=true for a HIGH-only result (no criticals)")
	}
}

// The same title from two scanners collapses to one finding, keeping the higher
// severity; distinct titles are preserved.
func TestDedupKeepsHighestSeverity(t *testing.T) {
	out := dedup([]Finding{
		{Source: "privacy", Severity: "WARN", Title: "Missing X"},
		{Source: "ipa", Severity: "CRITICAL", Title: "Missing X"},
		{Source: "codescan", Severity: "HIGH", Title: "Other"},
	})
	if len(out) != 2 {
		t.Fatalf("expected 2 findings after dedup, got %d: %+v", len(out), out)
	}
	for _, f := range out {
		if f.Title == "Missing X" && f.Severity != "CRITICAL" {
			t.Errorf("dedup should keep CRITICAL for 'Missing X', got %s", f.Severity)
		}
	}
}
