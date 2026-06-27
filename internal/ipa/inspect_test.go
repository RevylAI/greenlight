package ipa

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"howett.net/plist"
)

func marshalPlist(t *testing.T, v interface{}, format int) []byte {
	t.Helper()
	b, err := plist.Marshal(v, format)
	if err != nil {
		t.Fatalf("marshal plist: %v", err)
	}
	return b
}

// buildIPA writes a zip with the given entries to a temp .ipa and returns its path.
func buildIPA(t *testing.T, entries map[string][]byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "app.ipa")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for name, data := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

func titles(r *InspectResult) []string {
	var ts []string
	for _, f := range r.Findings {
		ts = append(ts, f.Title)
	}
	return ts
}

func hasFinding(r *InspectResult, substr string) bool {
	for _, f := range r.Findings {
		if strings.Contains(f.Title, substr) {
			return true
		}
	}
	return false
}

// The core fix: a BINARY Info.plist / PrivacyInfo.xcprivacy must parse correctly.
// The old string-matching approach silently failed on binary plists, producing
// false "missing key" findings and never extracting the bundle id.
func TestInspectParsesBinaryPlist(t *testing.T) {
	info := marshalPlist(t, map[string]interface{}{
		"CFBundleIdentifier":         "com.example.app",
		"CFBundleName":               "Example",
		"CFBundleVersion":            "42",
		"CFBundleShortVersionString": "1.0.0",
		"NSCameraUsageDescription":   "", // empty -> CRITICAL
		"NSAppTransportSecurity": map[string]interface{}{
			"NSAllowsArbitraryLoads": true, // -> WARN
		},
	}, plist.BinaryFormat)

	priv := marshalPlist(t, map[string]interface{}{
		"NSPrivacyTracking":           false,
		"NSPrivacyAccessedAPITypes":   []interface{}{},
		"NSPrivacyCollectedDataTypes": []interface{}{},
	}, plist.BinaryFormat)

	ipa := buildIPA(t, map[string][]byte{
		"Payload/Example.app/Info.plist":                          info,
		"Payload/Example.app/PrivacyInfo.xcprivacy":               priv,
		"Payload/Example.app/Assets.car":                          []byte("compiled catalog"),
		"Payload/Example.app/LaunchScreen.storyboardc/Info.plist": []byte("x"),
	})

	res, err := Inspect(ipa)
	if err != nil {
		t.Fatal(err)
	}

	if res.BundleID != "com.example.app" {
		t.Errorf("BundleID = %q, want com.example.app (binary plist not parsed)", res.BundleID)
	}
	if hasFinding(res, "Missing CFBundleVersion") || hasFinding(res, "Missing CFBundleShortVersionString") {
		t.Errorf("false missing-version finding on a binary plist: %v", titles(res))
	}
	if hasFinding(res, "No app icon") {
		t.Errorf("false 'No app icon' CRITICAL with Assets.car present: %v", titles(res))
	}
	// ...but it isn't silent either: an unverifiable compiled catalog gets an INFO.
	if !hasFinding(res, "could not be verified") {
		t.Errorf("expected the Assets.car icon INFO; got %v", titles(res))
	}
	if hasFinding(res, "No launch storyboard") {
		t.Errorf("false launch-storyboard finding: %v", titles(res))
	}
	if !hasFinding(res, "Camera purpose string is empty") {
		t.Errorf("empty Camera purpose string not detected on binary plist: %v", titles(res))
	}
	if !hasFinding(res, "App Transport Security disabled") {
		t.Errorf("ATS arbitrary-loads not detected on binary plist: %v", titles(res))
	}
}

// XML plists must still parse (and a real missing key must still be reported).
func TestInspectParsesXMLPlistAndReportsMissingIcon(t *testing.T) {
	info := marshalPlist(t, map[string]interface{}{
		"CFBundleIdentifier": "com.example.xml",
		"CFBundleName":       "XMLApp",
		// CFBundleVersion intentionally omitted -> WARN
		"CFBundleShortVersionString": "2.0",
	}, plist.XMLFormat)

	ipa := buildIPA(t, map[string][]byte{
		"Payload/XMLApp.app/Info.plist": info,
		// No Assets.car and no AppIcon -> CRITICAL no icon.
		// No PrivacyInfo.xcprivacy -> CRITICAL.
	})

	res, err := Inspect(ipa)
	if err != nil {
		t.Fatal(err)
	}
	if res.BundleID != "com.example.xml" {
		t.Errorf("BundleID = %q, want com.example.xml", res.BundleID)
	}
	if !hasFinding(res, "Missing CFBundleVersion") {
		t.Errorf("expected a missing CFBundleVersion finding; got %v", titles(res))
	}
	if !hasFinding(res, "No app icon") {
		t.Errorf("expected 'No app icon' when neither loose icons nor Assets.car exist; got %v", titles(res))
	}
	if !hasFinding(res, "Missing PrivacyInfo.xcprivacy") {
		t.Errorf("expected missing privacy manifest finding; got %v", titles(res))
	}
}
