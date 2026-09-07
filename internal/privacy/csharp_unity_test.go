package privacy

import (
	"testing"
)

// Unity's PlayerPrefs is backed by NSUserDefaults on Apple platforms, so C#
// PlayerPrefs usage must surface as a UserDefaults required-reason API hit.
func TestPlayerPrefsIsUserDefaults(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Save.cs", "public static void SaveLevel(int lv) {\n    PlayerPrefs.SetInt(\"level\", lv);\n    PlayerPrefs.Save();\n}\n")

	res, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, api := range res.DetectedAPIs {
		if api == "User Defaults" {
			return
		}
	}
	t.Errorf("PlayerPrefs should be detected as User Defaults; DetectedAPIs=%v", res.DetectedAPIs)
}

// Unity's ATT binding (ATTrackingStatusBinding) is the prompt, so a tracking SDK
// alongside it must not report missing ATT.
func TestUnityATTRecognized(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Analytics.cs", "using AppsFlyerSDK;\nclass A { void S() { AppsFlyer.startSDK(); } }\n")
	writeFile(t, dir, "Att.cs", "ATTrackingStatusBinding.RequestAuthorizationTracking(OnAuthorized);\n")

	res, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, f := range res.Findings {
		if f.Guideline == "5.1.2" {
			t.Errorf("ATT binding present; should not flag missing ATT: %+v", f)
		}
	}
}

// A build post-processor that injects NSUserTrackingUsageDescription proves a
// purpose string ships — not that the app ever prompts. Declaring the string
// without calling requestTrackingAuthorization is itself a standard ATT
// rejection, so the key alone must leave 5.1.2 reported.
func TestATTPurposeStringAloneStillReports(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Analytics.cs", "using AppsFlyerSDK;\nclass A { void S() { AppsFlyer.startSDK(); } }\n")
	writeFile(t, dir, "PostBuild.cs", "plist.root.SetString(\"NSUserTrackingUsageDescription\", desc);\n")

	res, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, f := range res.Findings {
		if f.Guideline == "5.1.2" {
			return
		}
	}
	t.Errorf("purpose string without a prompt must still report 5.1.2; findings=%+v", res.Findings)
}
