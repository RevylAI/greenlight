package ipa

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"strings"

	"howett.net/plist"
)

// maxPlistBytes caps how much we read from a single zip entry, so a crafted IPA
// with a huge declared UncompressedSize64 can't exhaust memory.
const maxPlistBytes = 16 << 20 // 16 MiB — orders of magnitude above any real plist

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
		appDir          string
		files           = make(map[string]*zip.File)
		hasInfoPlist    bool
		hasPrivacyInfo  bool
		hasLaunchSB     bool
		hasAppIcon      bool
		hasAssetCatalog bool
		iconCount       int
		frameworkDirs   = make(map[string]bool)
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
		case rel == "Assets.car":
			// Modern apps compile their icons into the asset catalog rather than
			// shipping loose AppIcon*.png files.
			hasAssetCatalog = true
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

	// 4. App icon. Loose AppIcon*.png OR a compiled Assets.car both count.
	switch {
	case !hasAppIcon && !hasAssetCatalog:
		result.Findings = append(result.Findings, Finding{
			Severity:  "CRITICAL",
			Guideline: "2.3",
			Title:     "No app icon found in bundle",
			Detail:    "The IPA contains neither AppIcon assets nor a compiled asset catalog (Assets.car).",
			Fix:       "Add a 1024x1024 app icon to your asset catalog.",
		})
	case !hasAppIcon && hasAssetCatalog:
		// Icons ship inside the compiled catalog; we can't open Assets.car to
		// confirm an AppIcon set actually exists, so surface it instead of going
		// silent (Apple still rejects an app with no AppIcon under §2.3).
		result.Findings = append(result.Findings, Finding{
			Severity:  "INFO",
			Guideline: "2.3",
			Title:     "App icon could not be verified (compiled into Assets.car)",
			Detail:    "Icons appear to ship inside the asset catalog; greenlight can't decode Assets.car to confirm a complete AppIcon set.",
			Fix:       "Confirm your asset catalog has an AppIcon set with a 1024x1024 marketing icon.",
		})
	case hasAppIcon && !hasAssetCatalog && iconCount < 2:
		// Only meaningful when icons ship as loose PNGs; a compiled catalog hides
		// the per-size files, so we can't (and shouldn't) count them.
		result.Findings = append(result.Findings, Finding{
			Severity:  "WARN",
			Guideline: "2.3",
			Title:     fmt.Sprintf("Only %d app icon size(s) found", iconCount),
			Detail:    "Multiple icon sizes are typically required for different devices.",
			Fix:       "Ensure your asset catalog includes icons for all required sizes.",
		})
	}

	// 5. App size. Note: this is the compressed IPA (the delivery artifact), not
	// the App Store-thinned per-device download, so treat it as an upper bound.
	sizeMB := float64(result.Size) / (1024 * 1024)
	if sizeMB > 200 {
		result.Findings = append(result.Findings, Finding{
			Severity:  "WARN",
			Guideline: "2.4",
			Title:     fmt.Sprintf("IPA size is %.0fMB — may exceed the cellular download limit", sizeMB),
			Detail:    "Apps over 200MB cannot be downloaded over cellular without user confirmation. The thinned per-device size is usually smaller than the IPA.",
			Fix:       "Consider On Demand Resources, app thinning, or reducing asset sizes.",
		})
	} else if sizeMB > 150 {
		result.Findings = append(result.Findings, Finding{
			Severity: "INFO",
			Title:    fmt.Sprintf("IPA size is %.0fMB — approaching the cellular limit", sizeMB),
			Detail:   "The 200MB cellular download limit may impact conversion rates.",
		})
	}

	// 6. Embedded frameworks should ship their own privacy manifests.
	for fw := range frameworkDirs {
		// fw is the bundle path relative to the app (e.g. "Frameworks/Foo.framework").
		if _, ok := files[appDir+fw+"/PrivacyInfo.xcprivacy"]; !ok {
			result.Findings = append(result.Findings, Finding{
				Severity:  "WARN",
				Guideline: "5.1.1",
				Title:     fmt.Sprintf("Framework '%s' missing privacy manifest", baseName(fw)),
				Detail:    "Third-party frameworks must include their own PrivacyInfo.xcprivacy.",
				Fix:       "Update the framework to a version that includes a privacy manifest, or contact the vendor.",
			})
		}
	}

	return result, nil
}

// parsePlist reads and decodes a plist zip entry. plist.Unmarshal auto-detects
// binary (bplist00) vs XML, so production binary plists parse correctly — the
// previous string-matching approach silently failed on them.
func parsePlist(files map[string]*zip.File, name string) (map[string]interface{}, error) {
	f, ok := files[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	data, err := io.ReadAll(io.LimitReader(rc, maxPlistBytes))
	if err != nil {
		return nil, err
	}

	var raw interface{}
	if _, err := plist.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	m, ok := raw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("plist root is not a dictionary")
	}
	return m, nil
}

func (r *InspectResult) checkInfoPlist(files map[string]*zip.File, appDir string) {
	m, err := parsePlist(files, appDir+"Info.plist")
	if err != nil {
		r.Findings = append(r.Findings, Finding{
			Severity: "INFO",
			Title:    "Could not parse Info.plist",
			Detail:   fmt.Sprintf("Info.plist is present but could not be decoded (%v); skipping its checks.", err),
		})
		return
	}

	if s := stringValue(m, "CFBundleIdentifier"); s != "" {
		r.BundleID = s
	}

	// Build/version numbers are required.
	for _, rk := range []struct{ key, guideline, title string }{
		{"CFBundleVersion", "2.1", "Missing CFBundleVersion (build number)"},
		{"CFBundleShortVersionString", "2.1", "Missing CFBundleShortVersionString (version)"},
	} {
		if stringValue(m, rk.key) == "" {
			r.Findings = append(r.Findings, Finding{
				Severity:  "WARN",
				Guideline: rk.guideline,
				Title:     rk.title,
				Detail:    fmt.Sprintf("Info.plist should contain a non-empty %s.", rk.key),
				Fix:       "Set the missing key in your build settings / Info.plist.",
			})
		}
	}

	// A display name is good practice; only flag when neither it nor CFBundleName
	// is set (CFBundleName is the fallback Apple uses).
	if stringValue(m, "CFBundleDisplayName") == "" && stringValue(m, "CFBundleName") == "" {
		r.Findings = append(r.Findings, Finding{
			Severity:  "WARN",
			Guideline: "2.3",
			Title:     "Missing CFBundleDisplayName / CFBundleName",
			Detail:    "The app has no display name set.",
			Fix:       "Set CFBundleDisplayName (or at least CFBundleName) in your Info.plist.",
		})
	}

	// App Transport Security: a global arbitrary-loads exception needs justification.
	if ats, ok := m["NSAppTransportSecurity"].(map[string]interface{}); ok {
		if allow, _ := ats["NSAllowsArbitraryLoads"].(bool); allow {
			r.Findings = append(r.Findings, Finding{
				Severity:  "WARN",
				Guideline: "1.6",
				Title:     "App Transport Security disabled (NSAllowsArbitraryLoads = true)",
				Detail:    "Disabling ATS globally allows insecure HTTP connections. Apple may require justification.",
				Fix:       "Use HTTPS everywhere, or scope exceptions per-domain via NSExceptionDomains instead of a global override.",
			})
		}
	}

	// Purpose strings: present-but-empty is a hard rejection; very short is vague.
	for _, ps := range purposeStrings {
		v, present := m[ps.key]
		if !present {
			continue
		}
		s, _ := v.(string)
		switch n := len([]rune(strings.TrimSpace(s))); {
		case n == 0:
			r.Findings = append(r.Findings, Finding{
				Severity:  "CRITICAL",
				Guideline: "5.1.1",
				Title:     fmt.Sprintf("%s purpose string is empty", ps.name),
				Detail:    fmt.Sprintf("%s is declared but has no description.", ps.key),
				Fix:       fmt.Sprintf("Add a specific, user-facing description for why your app needs %s access.", ps.name),
			})
		case n < 15:
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

func (r *InspectResult) checkPrivacyManifest(files map[string]*zip.File, appDir string) {
	m, err := parsePlist(files, appDir+"PrivacyInfo.xcprivacy")
	if err != nil {
		r.Findings = append(r.Findings, Finding{
			Severity: "INFO",
			Title:    "Could not parse PrivacyInfo.xcprivacy",
			Detail:   fmt.Sprintf("The privacy manifest is present but could not be decoded (%v); skipping its checks.", err),
		})
		return
	}

	if len(m) == 0 {
		r.Findings = append(r.Findings, Finding{
			Severity:  "WARN",
			Guideline: "5.1.1",
			Title:     "PrivacyInfo.xcprivacy is empty",
			Detail:    "The privacy manifest exists but declares nothing.",
			Fix:       "Populate the privacy manifest with your app's actual API usage and tracking declarations.",
		})
		return
	}

	if _, ok := m["NSPrivacyTracking"]; !ok {
		r.Findings = append(r.Findings, Finding{
			Severity:  "WARN",
			Guideline: "5.1.2",
			Title:     "Privacy manifest missing NSPrivacyTracking declaration",
			Detail:    "The privacy manifest should declare whether the app tracks users.",
			Fix:       "Add NSPrivacyTracking (boolean) to your PrivacyInfo.xcprivacy.",
		})
	}

	if _, ok := m["NSPrivacyAccessedAPITypes"]; !ok {
		r.Findings = append(r.Findings, Finding{
			Severity:  "WARN",
			Guideline: "5.1.1",
			Title:     "Privacy manifest missing NSPrivacyAccessedAPITypes",
			Detail:    "Required Reason APIs must be declared in the privacy manifest.",
			Fix:       "Declare all Required Reason API usage in NSPrivacyAccessedAPITypes.",
		})
	}

	if _, ok := m["NSPrivacyCollectedDataTypes"]; !ok {
		r.Findings = append(r.Findings, Finding{
			Severity:  "INFO",
			Guideline: "5.1.1",
			Title:     "Privacy manifest does not declare collected data types",
			Detail:    "NSPrivacyCollectedDataTypes should list what data your app collects.",
			Fix:       "Declare collected data types to match your App Store privacy nutrition labels.",
		})
	}
}

// purposeStrings are the Info.plist usage-description keys whose values Apple
// reviews for clarity.
var purposeStrings = []struct {
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

// stringValue returns m[key] as a trimmed string, or "" if absent / not a string.
func stringValue(m map[string]interface{}, key string) string {
	s, _ := m[key].(string)
	return strings.TrimSpace(s)
}

// baseName returns the last path element of a slash-separated bundle path.
func baseName(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}
