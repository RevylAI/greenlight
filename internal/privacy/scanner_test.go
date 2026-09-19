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

// The remaining `X.*Y` tracking patterns had the same defect as the Google Ads one
// fixed in #30: an unanchored `.*` between two short tokens matches across unrelated
// code on the same line. `adjust.*sdk` is the worst of them — `adjustsFontSizeToFitWidth`
// and `adjustedContentInset` are ordinary UIKit, so any line carrying one of those and
// the letters `sdk` produced a CRITICAL §5.1.2 finding.
func TestTrackingPatternsIgnoreOrdinaryCode(t *testing.T) {
	clean := []struct {
		name    string
		file    string
		content string
		notSDK  string
	}{
		{"uikit adjusts + sdk", "Label.swift",
			"label.adjustsFontSizeToFitWidth = true // call before sdkInit()\n", "Adjust SDK"},
		{"scrollview inset + sdk", "Scroll.swift",
			"scrollView.adjustedContentInset = insets; let sdkReady = true\n", "Adjust SDK"},
		{"unity webview + threads", "Unity.ts",
			"unityWebView.loadThreads();\n", "Unity Ads"},
		{"unity bridge + uploads", "Bridge.ts",
			"const unityBridge = init(); const uploads = [];\n", "Unity Ads"},
		{"google id + analytics flag", "config.ts",
			"export const cfg = { googleClientId: ID, analyticsEnabled: false };\n", "Google Analytics"},
		{"firebase auth + analytics word", "auth.ts",
			"import { getAuth } from 'firebase/auth'; // analytics intentionally omitted\n", "Firebase Analytics"},
		{"facebook login without sdk token", "fb.ts",
			"// the facebook login flow was removed; see sdkMigration.md\n", "Facebook SDK"},
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
				if sdk == tc.notSDK {
					t.Errorf("reported %q for ordinary code; content=%q", tc.notSDK, tc.content)
				}
			}
		})
	}
}

// Anchoring those patterns must not lose the integrations they exist to catch.
func TestTrackingPatternsStillDetectRealSDKs(t *testing.T) {
	real := []struct {
		name    string
		file    string
		content string
		wantSDK string
	}{
		{"adjust swift import", "A.swift", "import AdjustSdk\n", "Adjust SDK"},
		{"adjust api call", "A.swift", "Adjust.appDidLaunch(adjustConfig)\n", "Adjust SDK"},
		{"adjust react native", "a.ts", "import { Adjust } from 'react-native-adjust';\n", "Adjust SDK"},
		{"unity ads swift", "U.swift", "import UnityAds\n", "Unity Ads"},
		{"unity ads package", "u.ts", "import { UnityAds } from 'unity-ads-react-native';\n", "Unity Ads"},
		{"google analytics", "g.ts", "import ga from 'react-native-google-analytics';\n", "Google Analytics"},
		{"firebase analytics rn", "f.ts", "import analytics from '@react-native-firebase/analytics';\n", "Firebase Analytics"},
		{"firebase analytics modular", "f2.ts", "import { getAnalytics } from 'firebase/analytics';\n", "Firebase Analytics"},
		{"firebase analytics namespaced", "f3.js", "firebase.analytics().logEvent('open');\n", "Firebase Analytics"},
		{"firebase analytics compat", "f4.ts", "import 'firebase/compat/analytics';\n", "Firebase Analytics"},
		{"firebase analytics swift", "F.swift", "import FirebaseAnalytics\n", "Firebase Analytics"},
		{"facebook sdk rn", "fb.ts", "import { Settings } from 'react-native-fbsdk-next';\n", "Facebook SDK"},
		{"facebook sdk ios", "FB.m", "#import <FBSDKCoreKit/FBSDKCoreKit.h>\n", "Facebook SDK"},
		{"facebook ios sdk spm", "fb2.ts", "const dep = 'https://github.com/facebook/facebook-ios-sdk';\n", "Facebook SDK"},
		{"facebook jssdk loader", "fb3.js", "js.id = 'facebook-jssdk';\n", "Facebook SDK"},
		{"applovin", "al.swift", "import AppLovinSDK\n", "AppLovin"},
		{"ironsource", "is.swift", "import IronSource\n", "ironSource"},
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
				if sdk == tc.wantSDK {
					return
				}
			}
			t.Errorf("missed %q; content=%q TrackingSDKs=%v", tc.wantSDK, tc.content, res.TrackingSDKs)
		})
	}
}
