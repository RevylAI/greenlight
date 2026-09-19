package privacy

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Required Reason API detection must match real call sites that pass arguments —
// stat(path, &st) / statfs(&buf) — not only the argument-less stat() form, which
// essentially never appears in real source. The old `stat\(\)` patterns silently
// missed both categories.
func TestRequiredReasonDetectsRealCallSites(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Disk.swift", "func freeSpace() {\n  var b = statbuf\n  statfs(\"/\", &b)\n}\n")
	writeFile(t, dir, "Files.swift", "func when(path: String) {\n  var s = statbuf\n  stat(path, &s)\n}\n")

	res, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	want := map[string]bool{"Disk Space": false, "File Timestamp": false}
	for _, api := range res.DetectedAPIs {
		if _, ok := want[api]; ok {
			want[api] = true
		}
	}
	for api, found := range want {
		if !found {
			t.Errorf("expected %q detected from a real call site; DetectedAPIs=%v", api, res.DetectedAPIs)
		}
	}
}

// Tracking SDKs and the ATT call used to be matched against the whole file with
// MatchString(fullContent), which reads commented-out code as if it were live. The
// Required Reason scan in the same walk already skipped comments; these two did not.
func TestTrackingScanIgnoresComments(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Notes.swift", strings.Join([]string{
		"// We deliberately do not use mixpanel here.",
		"/* AppsFlyer was removed in v2.0 */",
		" * and so was applovin",
		"func body() { render() }",
	}, "\n")+"\n")

	res, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.TrackingSDKs) != 0 {
		t.Errorf("commented-out references counted as tracking SDKs: %v", res.TrackingSDKs)
	}
	for _, f := range res.Findings {
		if f.Guideline == "5.1.2" {
			t.Errorf("commented-out references produced a §5.1.2 finding: %+v", f)
		}
	}
}

// The inverse, and the more dangerous direction: an ATT call that only exists in a
// comment used to suppress the CRITICAL for an app that really does track.
func TestCommentedOutATTDoesNotSuppressFinding(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Tracking.swift", strings.Join([]string{
		"import AppsFlyerLib",
		"// TODO: call ATTrackingManager.requestTrackingAuthorization before this ships",
		"func start() { AppsFlyerLib.shared().start() }",
	}, "\n")+"\n")

	res, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	var found bool
	for _, f := range res.Findings {
		if f.Guideline == "5.1.2" {
			found = true
		}
	}
	if !found {
		t.Errorf("a commented-out ATT call suppressed the §5.1.2 finding; findings=%+v", res.Findings)
	}
}

// A trailing comment must not hide the code in front of it.
func TestTrackingScanStillReadsCodeWithTrailingComment(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "A.swift", "import AppsFlyerLib // analytics\n")

	res, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.TrackingSDKs) == 0 {
		t.Error("real SDK on a line with a trailing comment was not detected")
	}
}

// The §5.1.2 finding is the only CRITICAL that carried no location, which is exactly
// what makes a false positive hard to disprove. Finding already has File and Line.
func TestTrackingFindingCitesFileAndLine(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Analytics.swift", strings.Join([]string{
		"import Foundation",
		"import AppsFlyerLib",
		"func boot() {}",
	}, "\n")+"\n")

	res, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	for _, f := range res.Findings {
		if f.Guideline != "5.1.2" {
			continue
		}
		if f.File != "Analytics.swift" {
			t.Errorf("File = %q, want %q", f.File, "Analytics.swift")
		}
		if f.Line != 2 {
			t.Errorf("Line = %d, want 2", f.Line)
		}
		return
	}
	t.Fatalf("no §5.1.2 finding produced; findings=%+v", res.Findings)
}

// TrackingSDKs is built by ranging over a map, and Go randomises map iteration, so
// both the reported SDK list and the cited location used to change between runs on
// a project using more than one SDK. The list is sorted, and the citation is the
// genuinely earliest hit by file then line rather than whichever key came out first.
func TestTrackingFindingIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "A.swift", "import AppsFlyerLib\n")
	writeFile(t, dir, "B.swift", "import Mixpanel\n")
	writeFile(t, dir, "C.swift", "import AppLovinSDK\n")

	var first string
	for i := 0; i < 25; i++ {
		res, err := Scan(dir)
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}

		if want := []string{"AppLovin", "AppsFlyer", "Mixpanel"}; !slices.Equal(res.TrackingSDKs, want) {
			t.Fatalf("TrackingSDKs = %v, want %v (sorted)", res.TrackingSDKs, want)
		}

		var got string
		for _, f := range res.Findings {
			if f.Guideline == "5.1.2" {
				got = fmt.Sprintf("%s:%d|%s", f.File, f.Line, f.Detail)
			}
		}
		if got == "" {
			t.Fatalf("no §5.1.2 finding; findings=%+v", res.Findings)
		}
		if i == 0 {
			first = got
			if !strings.HasPrefix(got, "A.swift:1|") {
				t.Errorf("citation = %q, want the earliest hit A.swift:1", got)
			}
			continue
		}
		if got != first {
			t.Fatalf("finding changed between runs:\n  run 0: %s\n  run %d: %s", first, i, got)
		}
	}
}
