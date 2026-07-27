package preflight

import (
	"os"
	"path/filepath"
	"testing"
)

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

// An Android project must pick up Play findings from a plain preflight run,
// without the user naming a platform.
func TestRunDetectsAndroidProject(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, root, "app/build.gradle", "android {\n  defaultConfig {\n    targetSdk = 30\n  }\n}\n")
	mustWrite(t, root, "app/src/main/AndroidManifest.xml", `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
    <uses-permission android:name="android.permission.READ_SMS" />
    <application />
</manifest>`)

	result, err := Run(root, "", false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !result.IsAndroid {
		t.Fatal("Android project was not detected")
	}
	if result.PackageName != "com.example.app" {
		t.Errorf("PackageName = %q", result.PackageName)
	}

	var sawPlayFinding bool
	for _, f := range result.Findings {
		if f.Source == "playscan" {
			sawPlayFinding = true
			if f.Doc == "" {
				t.Errorf("play finding %q lost its Doc link through the preflight mapping", f.Title)
			}
		}
	}
	if !sawPlayFinding {
		t.Error("no playscan findings surfaced from preflight")
	}
}

// An iOS-only project must behave exactly as before: no Android state, no
// Play findings.
func TestRunLeavesIOSProjectsUnchanged(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, root, "app.json", `{"expo":{"name":"Demo","description":"d","version":"1.0.0","icon":"./icon.png","ios":{"bundleIdentifier":"com.example.demo"}}}`)
	mustWrite(t, root, "App.swift", "import SwiftUI\n")

	result, err := Run(root, "", false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.IsAndroid {
		t.Error("an iOS-only project was flagged as Android")
	}
	for _, f := range result.Findings {
		if f.Source == "playscan" {
			t.Errorf("unexpected Play finding on an iOS-only project: %s", f.Title)
		}
	}
}

func mustWrite(t *testing.T, root, rel, content string) {
	t.Helper()
	full := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// An Android-only repo must not be told it is missing an Apple privacy
// manifest. This was a real false positive: every pure-Android project led
// with a CRITICAL for an iOS-only requirement.
func TestAndroidOnlyProjectGetsNoAppleFindings(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, root, "app/build.gradle", "android {\n  defaultConfig {\n    targetSdk = 36\n  }\n}\n")
	mustWrite(t, root, "app/src/main/AndroidManifest.xml", `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
    <application />
</manifest>`)
	mustWrite(t, root, "app/src/main/java/com/example/app/MainActivity.kt", "package com.example.app\n")

	result, err := Run(root, "", false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range result.Findings {
		switch f.Source {
		case "privacy", "metadata", "codescan":
			t.Errorf("Apple scanner ran on an Android-only project: [%s] %s", f.Source, f.Title)
		}
	}
}

// A cross-platform repo must be checked against both stores in one pass.
func TestCrossPlatformProjectRunsBothScanners(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, root, "app.json", `{"expo":{"name":"Demo"}}`)
	mustWrite(t, root, "ios/Demo/Info.plist", "<plist></plist>")
	mustWrite(t, root, "android/app/build.gradle", "android {\n  defaultConfig {\n    targetSdk = 30\n  }\n}\n")
	mustWrite(t, root, "android/app/src/main/AndroidManifest.xml", `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.demo">
    <application />
</manifest>`)

	ios, android := DetectPlatforms(root)
	if !ios || !android {
		t.Fatalf("DetectPlatforms = (ios=%v, android=%v), want both", ios, android)
	}

	result, err := Run(root, "", false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var sawPlay, sawApple bool
	for _, f := range result.Findings {
		switch f.Source {
		case "playscan":
			sawPlay = true
		case "privacy", "metadata", "codescan":
			sawApple = true
		}
	}
	if !sawPlay {
		t.Error("no Play findings on a cross-platform project")
	}
	if !sawApple {
		t.Error("no Apple findings on a cross-platform project")
	}
}

// detectIOS decides whether the Apple scanners run at all, so a missed signal
// silently drops real findings. Each entry here is a file that codescan or the
// metadata scanner actually reads.
func TestDetectIOSRecognizesAllAppleSignals(t *testing.T) {
	signals := []string{
		"App.swift",
		"Legacy.m",
		"Legacy.mm",
		"Header.h",
		"MyApp/Info.plist",
		"Podfile",
		"Package.swift",
		"MyApp.xcodeproj/project.pbxproj",
		"app.json",
		"app.config.js",
		"app.config.ts",
		"app.config.json",
	}
	for _, signal := range signals {
		t.Run(signal, func(t *testing.T) {
			root := t.TempDir()
			// Paired with a real Android project, so a missed iOS signal would
			// classify the repo Android-only and skip the Apple scanners.
			mustWrite(t, root, "android/app/build.gradle", "android { defaultConfig { targetSdk = 36 } }")
			mustWrite(t, root, "android/app/src/main/AndroidManifest.xml",
				`<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x"><application /></manifest>`)
			mustWrite(t, root, signal, "{}")

			ios, android := DetectPlatforms(root)
			if !android {
				t.Fatal("android side not detected")
			}
			if !ios {
				t.Errorf("%s did not mark the project as iOS, so Apple checks would be skipped", signal)
			}
		})
	}
}

// A vendored dependency's Xcode project must not make an Android-only repo
// look like an iOS app.
func TestDetectIOSSkipsVendoredDirectories(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, root, "android/app/build.gradle", "android { defaultConfig { targetSdk = 36 } }")
	mustWrite(t, root, "node_modules/some-lib/ios/Thing.swift", "import Foundation")
	mustWrite(t, root, "Pods/Other/Info.plist", "<plist/>")

	if ios, _ := DetectPlatforms(root); ios {
		t.Error("vendored iOS sources should not classify the repo as iOS")
	}
}
