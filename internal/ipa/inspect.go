package ipa

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Finding from IPA inspection.
type Finding struct {
	Severity  string `json:"severity"` // CRITICAL, WARN, INFO
	Guideline string `json:"guideline,omitempty"`
	Title     string `json:"title"`
	Detail    string `json:"detail"`
	Fix       string `json:"fix,omitempty"`
}

// InspectResult holds the full IPA inspection output.
type InspectResult struct {
	IPAPath  string    `json:"ipa_path"`
	AppName  string    `json:"app_name"`
	BundleID string    `json:"bundle_id,omitempty"`
	Size     int64     `json:"size_bytes"`
	Findings []Finding `json:"findings"`
}

// Inspect analyzes an IPA file for App Store compliance issues.
func Inspect(ipaPath string) (*InspectResult, error) {
	info, err := os.Stat(ipaPath)
	if err != nil {
		return nil, fmt.Errorf("cannot access IPA: %w", err)
	}

	result := &InspectResult{
		IPAPath: ipaPath,
		Size:    info.Size(),
	}

	r, err := zip.OpenReader(ipaPath)
	if err != nil {
		return nil, fmt.Errorf("cannot open IPA (not a valid zip): %w", err)
	}
	defer r.Close()

	// Build an index of all files in the IPA
	var (
		appDir         string
		files          = make(map[string]*zip.File)
		hasInfoPlist   bool
		hasPrivacyInfo bool
		hasLaunchSB    bool
		hasAppIcon     bool
		iconCount      int
		frameworkDirs  = make(map[string]bool)
		archsFound     = make(map[string]bool)
	)

	for _, f := range r.File {
		files[f.Name] = f

		// Find the .app directory
		if appDir == "" {
			parts := strings.SplitN(f.Name, "/", 3)
			if len(parts) >= 2 && strings.HasSuffix(parts[1], ".app") {
				appDir = parts[0] + "/" + parts[1] + "/"
				result.AppName = strings.TrimSuffix(parts[1], ".app")
			}
		}
	}

	if appDir == "" {
		result.Findings = append(result.Findings, Finding{
			Severity: "CRITICAL",
			Title:    "Invalid IPA structure",
			Detail:   "No .app bundle found inside the IPA.",
			Fix:      "Ensure you're inspecting a valid IPA built for distribution.",
		})
		return result, nil
	}

	// Check all files relative to the app bundle
	for name := range files {
		if !strings.HasPrefix(name, appDir) {
			continue
		}
		rel := strings.TrimPrefix(name, appDir)

		switch {
		case rel == "Info.plist":
			hasInfoPlist = true
		case rel == "PrivacyInfo.xcprivacy":
			hasPrivacyInfo = true
		case strings.Contains(rel, "LaunchScreen") || strings.Contains(rel, "LaunchStoryboard"):
			hasLaunchSB = true
		case strings.HasPrefix(rel, "AppIcon") || strings.Contains(rel, "AppIcon"):
			hasAppIcon = true
			if strings.HasSuffix(rel, ".png") {
				iconCount++
			}
		case strings.Contains(rel, ".framework/"):
			parts := strings.SplitN(rel, ".framework/", 2)
			frameworkDirs[parts[0]+".framework"] = true
		}

		// Check for executable to detect architectures
		if rel == result.AppName {
			archsFound["binary"] = true
		}
	}

	// --- Run checks ---

	// 1. Info.plist
	if !hasInfoPlist {
		result.Findings = append(result.Findings, Finding{
			Severity:  "CRITICAL",
			Guideline: "2.1",
			Title:     "Missing Info.plist",
			Detail:    "The app bundle does not contain an Info.plist file.",
			Fix:       "This indicates a broken build. Rebuild your app.",
		})
	} else {
		// Parse Info.plist and check contents
		result.checkInfoPlist(files, appDir)
	}

	// 2. PrivacyInfo.xcprivacy (required since Spring 2024)
	if !hasPrivacyInfo {
		result.Findings = append(result.Findings, Finding{
			Severity:  "CRITICAL",
			Guideline: "5.1.1",
			Title:     "Missing PrivacyInfo.xcprivacy",
			Detail:    "Privacy manifest is required since May 2024. Apps without it receive ITMS-91061 rejection.",
			Fix:       "Add a PrivacyInfo.xcprivacy file to your app target. See: developer.apple.com/documentation/bundleresources/privacy-manifest-files",
		})
	} else {
		result.checkPrivacyManifest(files, appDir)
	}

	// 3. Launch storyboard
	if !hasLaunchSB {
		result.Findings = append(result.Findings, Finding{
			Severity:  "WARN",
			Guideline: "4.2",
			Title:     "No launch storyboard detected",
			Detail:    "Apps must use a launch storyboard (not a static launch image) for all device sizes.",
			Fix:       "Add a LaunchScreen.storyboard to your project.",
		})
	}

	// 4. App icon
	if !hasAppIcon {
		result.Findings = append(result.Findings, Finding{
			Severity:  "CRITICAL",
			Guideline: "2.3",
			Title:     "No app icon found in bundle",
			Detail:    "The IPA does not contain any AppIcon assets.",
			Fix:       "Add a 1024x1024 app icon to your asset catalog.",
		})
	} else if iconCount < 2 {
		result.Findings = append(result.Findings, Finding{
			Severity:  "WARN",
			Guideline: "2.3",
			Title:     fmt.Sprintf("Only %d app icon size(s) found", iconCount),
			Detail:    "Multiple icon sizes are typically required for different devices.",
			Fix:       "Ensure your asset catalog includes icons for all required sizes.",
		})
	}

	// 5. App size
	sizeMB := float64(result.Size) / (1024 * 1024)
	if sizeMB > 200 {
		result.Findings = append(result.Findings, Finding{
			Severity:  "WARN",
			Guideline: "2.4",
			Title:     fmt.Sprintf("App size is %.0fMB — exceeds cellular download limit", sizeMB),
			Detail:    "Apps over 200MB cannot be downloaded over cellular data without user confirmation.",
			Fix:       "Consider using On Demand Resources, app thinning, or reducing asset sizes.",
		})
	} else if sizeMB > 150 {
		result.Findings = append(result.Findings, Finding{
			Severity: "INFO",
			Title:    fmt.Sprintf("App size is %.0fMB — approaching cellular limit", sizeMB),
			Detail:   "The 200MB cellular download limit may impact conversion rates.",
		})
	}

	// 6. Check embedded frameworks for their own privacy manifests
	for fw := range frameworkDirs {
		fwPrivacy := appDir + "Frameworks/" + fw + "/PrivacyInfo.xcprivacy"
		if _, ok := files[fwPrivacy]; !ok {
			// Also check without Frameworks/ prefix
			fwPrivacy2 := appDir + fw + "/PrivacyInfo.xcprivacy"
			if _, ok := files[fwPrivacy2]; !ok {
				result.Findings = append(result.Findings, Finding{
					Severity:  "WARN",
					Guideline: "5.1.1",
					Title:     fmt.Sprintf("Framework '%s' missing privacy manifest", filepath.Base(fw)),
					Detail:    "Third-party frameworks must include their own PrivacyInfo.xcprivacy.",
					Fix:       "Update the framework to a version that includes a privacy manifest, or contact the vendor.",
				})
			}
		}
	}

	return result, nil
}

func (r *InspectResult) checkInfoPlist(files map[string]*zip.File, appDir string) {
	f, ok := files[appDir+"Info.plist"]
	if !ok {
		return
	}

	rc, err := f.Open()
	if err != nil {
		return
	}
	defer rc.Close()

	// Read as bytes — Info.plist can be binary or XML
	buf := make([]byte, f.UncompressedSize64)
	rc.Read(buf)
	content := string(buf)

	// Check for required keys (works for XML plists; binary plists will have partial matches)
	requiredKeys := map[string]struct {
		guideline string
		title     string
	}{
		"CFBundleDisplayName":        {"2.3", "Missing CFBundleDisplayName"},
		"CFBundleVersion":            {"2.1", "Missing CFBundleVersion (build number)"},
		"CFBundleShortVersionString": {"2.1", "Missing CFBundleShortVersionString (version)"},
	}

	for key, info := range requiredKeys {
		if !strings.Contains(content, key) {
			r.Findings = append(r.Findings, Finding{
				Severity:  "WARN",
				Guideline: info.guideline,
				Title:     info.title,
				Detail:    fmt.Sprintf("Info.plist should contain %s.", key),
				Fix:       "Add the missing key to your Info.plist.",
			})
		}
	}

	// Check for NSAppTransportSecurity exceptions
	if strings.Contains(content, "NSAllowsArbitraryLoads") {
		if strings.Contains(content, "<true/>") {
			r.Findings = append(r.Findings, Finding{
				Severity:  "WARN",
				Guideline: "1.6",
				Title:     "App Transport Security disabled (NSAllowsArbitraryLoads = true)",
				Detail:    "Disabling ATS allows insecure HTTP connections. Apple may require justification.",
				Fix:       "Use HTTPS for all connections instead of disabling ATS globally. Use per-domain exceptions if needed.",
			})
		}
	}

	// Check for purpose strings (they should exist if capabilities are used)
	purposeStrings := []struct {
		key  string
		name string
	}{
		{"NSCameraUsageDescription", "Camera"},
		{"NSMicrophoneUsageDescription", "Microphone"},
		{"NSPhotoLibraryUsageDescription", "Photo Library"},
		{"NSLocationWhenInUseUsageDescription", "Location (When In Use)"},
		{"NSLocationAlwaysUsageDescription", "Location (Always)"},
		{"NSBluetoothAlwaysUsageDescription", "Bluetooth"},
		{"NSMotionUsageDescription", "Motion"},
		{"NSFaceIDUsageDescription", "Face ID"},
		{"NSUserTrackingUsageDescription", "User Tracking (ATT)"},
		{"NSHealthShareUsageDescription", "HealthKit"},
		{"NSContactsUsageDescription", "Contacts"},
		{"NSCalendarsUsageDescription", "Calendars"},
		{"NSRemindersUsageDescription", "Reminders"},
		{"NSSpeechRecognitionUsageDescription", "Speech Recognition"},
	}

	// Check for empty purpose strings
	for _, ps := range purposeStrings {
		if strings.Contains(content, ps.key) {
			// Check for empty or very short value
			emptyPattern := regexp.MustCompile(ps.key + `</key>\s*<string>\s*</string>`)
			shortPattern := regexp.MustCompile(ps.key + `</key>\s*<string>.{1,15}</string>`)
			if emptyPattern.Match(buf) {
				r.Findings = append(r.Findings, Finding{
					Severity:  "CRITICAL",
					Guideline: "5.1.1",
					Title:     fmt.Sprintf("%s purpose string is empty", ps.name),
					Detail:    fmt.Sprintf("%s is declared but has no description.", ps.key),
					Fix:       fmt.Sprintf("Add a specific, user-facing description for why your app needs %s access.", ps.name),
				})
			} else if shortPattern.Match(buf) {
				r.Findings = append(r.Findings, Finding{
					Severity:  "WARN",
					Guideline: "5.1.1",
					Title:     fmt.Sprintf("%s purpose string may be too vague", ps.name),
					Detail:    fmt.Sprintf("%s has a very short description. Apple rejects vague purpose strings.", ps.key),
					Fix:       "Write a specific description: 'Take photos to attach to support tickets' NOT 'Camera access needed'.",
				})
			}
		}
	}
}

func (r *InspectResult) checkPrivacyManifest(files map[string]*zip.File, appDir string) {
	f, ok := files[appDir+"PrivacyInfo.xcprivacy"]
	if !ok {
		return
	}

	rc, err := f.Open()
	if err != nil {
		return
	}
	defer rc.Close()

	buf := make([]byte, f.UncompressedSize64)
	rc.Read(buf)
	content := string(buf)

	// Check if it's basically empty
	if len(strings.TrimSpace(content)) < 100 {
		r.Findings = append(r.Findings, Finding{
			Severity:  "WARN",
			Guideline: "5.1.1",
			Title:     "PrivacyInfo.xcprivacy appears to be minimal/empty",
			Detail:    "The privacy manifest exists but may not declare any API usage or tracking.",
			Fix:       "Populate the privacy manifest with your app's actual API usage and tracking declarations.",
		})
	}

	// Check for NSPrivacyTracking declaration
	if !strings.Contains(content, "NSPrivacyTracking") {
		r.Findings = append(r.Findings, Finding{
			Severity:  "WARN",
			Guideline: "5.1.2",
			Title:     "Privacy manifest missing NSPrivacyTracking declaration",
			Detail:    "The privacy manifest should declare whether the app tracks users.",
			Fix:       "Add NSPrivacyTracking (boolean) to your PrivacyInfo.xcprivacy.",
		})
	}

	// Check for NSPrivacyAccessedAPITypes
	if !strings.Contains(content, "NSPrivacyAccessedAPITypes") {
		r.Findings = append(r.Findings, Finding{
			Severity:  "WARN",
			Guideline: "5.1.1",
			Title:     "Privacy manifest missing NSPrivacyAccessedAPITypes",
			Detail:    "Required Reason APIs must be declared in the privacy manifest.",
			Fix:       "Declare all Required Reason API usage in NSPrivacyAccessedAPITypes.",
		})
	}

	// Check for NSPrivacyCollectedDataTypes
	if !strings.Contains(content, "NSPrivacyCollectedDataTypes") {
		r.Findings = append(r.Findings, Finding{
			Severity:  "INFO",
			Guideline: "5.1.1",
			Title:     "Privacy manifest does not declare collected data types",
			Detail:    "NSPrivacyCollectedDataTypes should list what data your app collects.",
			Fix:       "Declare collected data types to match your App Store privacy nutrition labels.",
		})
	}
}
