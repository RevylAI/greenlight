package privacy

import (
	"os"
	"path/filepath"
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

// The Google Ads/AdMob pattern used to be `google.*ads`, which is unanchored and
// case-insensitive, so `ads` matched inside ordinary identifiers — `loadSdk`,
// `downloads`, `uploads`, `threads`. Any app that touched a non-ad Google SDK and
// happened to have one of those words on the same line got a CRITICAL §5.1.2
// finding telling it to add an ATT prompt it does not need, and `--exit-code`
// failed the build. https://github.com/RevylAI/greenlight/issues/30
func TestGoogleAdsPatternIgnoresOrdinaryIdentifiers(t *testing.T) {
	clean := []struct {
		name    string
		file    string
		content string
	}{
		{"google sign-in with loadSdk", "googleSignIn.ts",
			"GoogleSignin: Awaited<ReturnType<typeof loadSdk>>[\"GoogleSignin\"],\n"},
		{"google with downloads", "Downloads.swift",
			"let googleDriveDownloads = try await drive.downloads()\n"},
		{"google with threads", "Threads.ts",
			"const googleClient = build(); // threads are reused here\n"},
		{"google with uploads", "Uploads.ts",
			"import { GoogleAuthProvider } from \"firebase/auth\"; const uploads = [];\n"},
	}

	for _, tc := range clean {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, tc.file, tc.content)

			res, err := Scan(dir)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			for _, sdk := range res.TrackingSDKs {
				if sdk == "Google Ads/AdMob" {
					t.Errorf("reported Google Ads/AdMob for an app with no ad SDK; content=%q", tc.content)
				}
			}
		})
	}
}

// Anchoring the pattern must not cost us any real AdMob integration. These are the
// forms that appear in the file types detectLang actually scans — Swift, Objective-C
// and JS/TS. Manifest files like Info.plist, Podfile and package.json are not scanned
// at all today, so GADApplicationIdentifier is kept in the pattern for the Swift and
// Objective-C call sites rather than for the plist key.
func TestGoogleAdsPatternStillDetectsRealIntegrations(t *testing.T) {
	real := []struct {
		name    string
		file    string
		content string
	}{
		{"swift import", "Ads.swift", "import GoogleMobileAds\n"},
		{"swift api", "Ads.swift", "GADMobileAds.sharedInstance().start(completionHandler: nil)\n"},
		{"objc identifier", "Ads.m", "NSString *key = @\"GADApplicationIdentifier\";\n"},
		{"react native import", "ads.ts", "import mobileAds from 'react-native-google-mobile-ads';\n"},
		{"expo admob component", "Banner.tsx", "import { AdMobBanner } from 'expo-ads-admob';\n"},
		{"bare admob token", "ads.js", "const admob = require('admob');\n"},
	}

	for _, tc := range real {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, tc.file, tc.content)

			res, err := Scan(dir)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			for _, sdk := range res.TrackingSDKs {
				if sdk == "Google Ads/AdMob" {
					return
				}
			}
			t.Errorf("missed a real AdMob integration; content=%q TrackingSDKs=%v", tc.content, res.TrackingSDKs)
		})
	}
}
