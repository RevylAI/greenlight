package privacy

import (
	"os"
	"path/filepath"
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

// The bare stat()/fstat()/lstat() patterns were case-insensitive, so on a
// React/React Native project (TS/JS is in File Timestamp's Languages list)
// they matched any PascalCase identifier shaped like `function Stat(...)`
// — the common component-naming convention for a small stat-display widget
// — and produced a CRITICAL "Required Reason API used but not declared"
// finding on apps that never touch a real file-timestamp API. Found by
// running greenlight against runner-map, which declares nine such `Stat`
// components across its screens/components.
func TestFileTimestampPatternIgnoresPascalCaseStatComponent(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "StatCard.tsx", `
function Stat({ label, value }: { label: string; value: string }) {
  return <View><Text>{label}</Text><Text>{value}</Text></View>;
}
`)

	res, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	for _, api := range res.DetectedAPIs {
		if api == "File Timestamp" {
			t.Fatalf("a `function Stat(...)` component falsely matched as File Timestamp API usage; DetectedAPIs=%v", res.DetectedAPIs)
		}
	}
	for _, f := range res.Findings {
		if strings.Contains(f.Title, "File Timestamp") {
			t.Fatalf("expected no File Timestamp finding for a Stat() component, got: %+v", f)
		}
	}
}

// The old `google.*ads` pattern was unanchored and case-insensitive, so it
// matched "ads" inside ordinary identifiers like `loadSdk`, `downloads`, or
// `uploads` whenever "google" appeared earlier on the same line. That
// produced a CRITICAL "Tracking SDKs detected without ATT implementation"
// finding — the top severity, gating --exit-code — on apps that use Google
// Sign-In (or any other Google SDK) but ship no advertising SDK at all.
// Regression for the exact repro from upstream issue #30.
func TestGoogleAdsPatternIgnoresUnrelatedGoogleSDKs(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "googleSignIn.ts", `
type SignInModule = {
  GoogleSignin: Awaited<ReturnType<typeof loadSdk>>["GoogleSignin"],
}
`)

	res, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	for _, sdk := range res.TrackingSDKs {
		if sdk == "Google Ads/AdMob" {
			t.Fatalf("Google Sign-In's `loadSdk` falsely matched as Google Ads/AdMob; TrackingSDKs=%v", res.TrackingSDKs)
		}
	}
	for _, f := range res.Findings {
		if f.Guideline == "5.1.2" {
			t.Fatalf("expected no ATT finding for an app with no tracking SDK, got: %+v", f)
		}
	}
}

// A real AdMob integration must still be caught — the fix narrows the
// pattern, it must not blind it.
func TestGoogleAdsPatternStillDetectsRealAdMob(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Ads.swift", `import GoogleMobileAds

func loadAd() {
  GADMobileAds.sharedInstance().start(completionHandler: nil)
}
`)

	res, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	found := false
	for _, sdk := range res.TrackingSDKs {
		if sdk == "Google Ads/AdMob" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected real AdMob usage (GADMobileAds) to be detected; TrackingSDKs=%v", res.TrackingSDKs)
	}

	hasATTFinding := false
	for _, f := range res.Findings {
		if f.Guideline == "5.1.2" {
			hasATTFinding = true
		}
	}
	if !hasATTFinding {
		t.Fatalf("expected an ATT finding since the app ships AdMob with no ATT call")
	}
}

// Same shape of bug for Unity Ads: a bare `unity.*ads` wildcard could match
// "unity" and an unrelated "...ads..." substring anywhere later on the same
// line. The tightened pattern requires one of the real Unity Ads tokens.
func TestUnityAdsPatternIgnoresUnrelatedSubstring(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "unityBridge.ts", `
// Pulls build artifacts for the Unity player, nothing to do with ads.
async function loadUnityDownloads() {
  return fetchUnityBuildDownloads();
}
`)

	res, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, sdk := range res.TrackingSDKs {
		if sdk == "Unity Ads" {
			t.Fatalf("unrelated unity/downloads text falsely matched as Unity Ads; TrackingSDKs=%v", res.TrackingSDKs)
		}
	}
}
