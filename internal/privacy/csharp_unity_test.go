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

// Unity's ATT binding (ATTrackingStatusBinding) and a build post-processor that
// injects NSUserTrackingUsageDescription both count as ATT implementations, so
// a tracking SDK alongside either must not report missing ATT.
func TestUnityATTRecognized(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Analytics.cs", "using AppsFlyerSDK;\nclass A { void S() { AppsFlyer.startSDK(); } }\n")
	writeFile(t, dir, "PostBuild.cs", "plist.root.SetString(\"NSUserTrackingUsageDescription\", desc);\n")

	res, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, f := range res.Findings {
		if f.Guideline == "5.1.2" {
			t.Errorf("ATT handled via post-build injection; should not flag missing ATT: %+v", f)
		}
	}
}
