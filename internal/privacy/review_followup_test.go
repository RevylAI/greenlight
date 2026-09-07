package privacy

import (
	"os"
	"path/filepath"
	"testing"
)

func mkUnityProject(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "ProjectSettings"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "ProjectSettings"), "ProjectSettings.asset", "m_EditorVersion: 6000.3.9f1\n")
	return root
}

const depManifest = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>NSPrivacyAccessedAPITypes</key><array><dict>
    <key>NSPrivacyAccessedAPIType</key><string>NSPrivacyAccessedAPICategoryFileTimestamp</string>
  </dict></array>
</dict></plist>
`

// A Unity package's own PrivacyInfo.xcprivacy lives under Library/PackageCache.
// Reading it as the app's manifest reports the app as compliant when it has no
// manifest at all — the CRITICAL this scanner exists to catch.
func TestDependencyManifestIsNotTheAppManifest(t *testing.T) {
	root := mkUnityProject(t)
	pkg := filepath.Join(root, "Library", "PackageCache", "com.unity.ads@4.4.2", "Plugins", "iOS")
	if err := os.MkdirAll(pkg, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, pkg, "PrivacyInfo.xcprivacy", depManifest)
	writeFile(t, root, "Save.cs", "PlayerPrefs.SetInt(\"level\", 3);\n")

	res, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.HasPrivacyInfo {
		t.Error("a dependency's manifest under Library/PackageCache must not count as the app's")
	}
	var sawMissing bool
	for _, f := range res.Findings {
		if f.Severity == "CRITICAL" && f.Guideline == "5.1.1" {
			sawMissing = true
		}
	}
	if !sawMissing {
		t.Errorf("missing app manifest must stay CRITICAL; findings=%+v", res.Findings)
	}
}

// The app's own manifest still wins, and it is still read.
func TestAppManifestIsFound(t *testing.T) {
	root := mkUnityProject(t)
	writeFile(t, root, "PrivacyInfo.xcprivacy", depManifest)

	res, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !res.HasPrivacyInfo {
		t.Fatal("the app's own PrivacyInfo.xcprivacy must be found")
	}
	if len(res.DeclaredAPIs) == 0 {
		t.Error("declared APIs must be parsed from the app manifest")
	}
}
