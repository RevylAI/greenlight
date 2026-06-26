package preflight

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// AppMeta holds metadata extracted from project config files.
type AppMeta struct {
	AppName  string
	BundleID string
	Version  string
	Source   string // "app.json", "Info.plist", "pbxproj"
}

// CheckLocalMetadata reads project config files and flags issues that
// would normally require App Store Connect to detect.
func CheckLocalMetadata(projectPath string) ([]Finding, AppMeta) {
	var findings []Finding
	var meta AppMeta

	// Try Expo/React Native first (app.json)
	appJSON := filepath.Join(projectPath, "app.json")
	if data, err := os.ReadFile(appJSON); err == nil {
		f, m := checkAppJSON(data)
		findings = append(findings, f...)
		meta = m
		meta.Source = "app.json"
	}

	// Try app.config.js/ts (check for presence, can't fully parse JS)
	for _, name := range []string{"app.config.js", "app.config.ts"} {
		configPath := filepath.Join(projectPath, name)
		if _, err := os.Stat(configPath); err == nil {
			if meta.Source == "" {
				meta.Source = name
			}
		}
	}

	// Try native iOS Info.plist locations
	plistPaths := findInfoPlists(projectPath)
	for _, ppath := range plistPaths {
		if data, err := os.ReadFile(ppath); err == nil {
			f, m := checkInfoPlistLocal(data, ppath, projectPath)
			findings = append(findings, f...)
			if meta.AppName == "" && m.AppName != "" {
				meta.AppName = m.AppName
			}
			if meta.BundleID == "" && m.BundleID != "" {
				meta.BundleID = m.BundleID
			}
			if meta.Version == "" && m.Version != "" {
				meta.Version = m.Version
			}
		}
	}

	// Check for privacy policy file or URL in config
	findings = append(findings, checkPrivacyPolicy(projectPath)...)

	return findings, meta
}

// expoConfig represents the relevant parts of app.json.
type expoConfig struct {
	Expo *struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Version     string `json:"version"`
		IOS         *struct {
			BundleIdentifier string                 `json:"bundleIdentifier"`
			SupportsTablet   *bool                  `json:"supportsTablet"`
			Icon             string                 `json:"icon"`
			InfoPlist        map[string]interface{} `json:"infoPlist"`
			PrivacyManifests interface{}            `json:"privacyManifests"`
		} `json:"ios"`
		Icon    string        `json:"icon"`
		Plugins []interface{} `json:"plugins"`
	} `json:"expo"`
}

func checkAppJSON(data []byte) ([]Finding, AppMeta) {
	var findings []Finding
	var meta AppMeta

	var cfg expoConfig
	if err := json.Unmarshal(data, &cfg); err != nil || cfg.Expo == nil {
		return findings, meta
	}

	expo := cfg.Expo
	meta.AppName = expo.Name
	meta.Version = expo.Version

	if expo.IOS != nil {
		meta.BundleID = expo.IOS.BundleIdentifier
	}

	// Check: app name
	if expo.Name == "" {
		findings = append(findings, Finding{
			Source:    "metadata",
			Severity:  "CRITICAL",
			Guideline: "2.3",
			Title:     "App name is missing in app.json",
			Detail:    "expo.name is empty. An app name is required for submission.",
			Fix:       "Set \"name\" in your app.json expo config.",
			File:      "app.json",
		})
	}

	// Check: description
	if expo.Description == "" {
		findings = append(findings, Finding{
			Source:    "metadata",
			Severity:  "WARN",
			Guideline: "2.3",
			Title:     "App description is missing in app.json",
			Detail:    "expo.description is empty. While not strictly required in app.json, having no description makes it likely you'll forget it in App Store Connect too.",
			Fix:       "Add a \"description\" field in your app.json for reference.",
			File:      "app.json",
		})
	}

	// Check: version
	if expo.Version == "" {
		findings = append(findings, Finding{
			Source:    "metadata",
			Severity:  "CRITICAL",
			Guideline: "2.1",
			Title:     "App version is missing in app.json",
			Detail:    "expo.version is empty. A version string is required.",
			Fix:       "Set \"version\" (e.g. \"1.0.0\") in your app.json.",
			File:      "app.json",
		})
	}

	// Check: bundle identifier
	if expo.IOS != nil {
		if expo.IOS.BundleIdentifier == "" {
			findings = append(findings, Finding{
				Source:    "metadata",
				Severity:  "CRITICAL",
				Guideline: "2.1",
				Title:     "iOS bundle identifier is missing",
				Detail:    "expo.ios.bundleIdentifier is empty. Required for App Store submission.",
				Fix:       "Set \"bundleIdentifier\" under expo.ios (e.g. \"com.company.appname\").",
				File:      "app.json",
			})
		} else {
			// Validate bundle ID format
			bundleIDPattern := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9]*(\.[a-zA-Z][a-zA-Z0-9]*)+$`)
			if !bundleIDPattern.MatchString(expo.IOS.BundleIdentifier) {
				findings = append(findings, Finding{
					Source:    "metadata",
					Severity:  "WARN",
					Guideline: "2.1",
					Title:     "Bundle identifier format may be invalid",
					Detail:    "\"" + expo.IOS.BundleIdentifier + "\" — bundle IDs should be reverse-domain notation (e.g. com.company.app).",
					Fix:       "Use reverse-domain notation with only letters, numbers, and dots.",
					File:      "app.json",
				})
			}
		}

		// Check: app icon
		icon := expo.IOS.Icon
		if icon == "" {
			icon = expo.Icon
		}
		if icon == "" {
			findings = append(findings, Finding{
				Source:    "metadata",
				Severity:  "CRITICAL",
				Guideline: "2.3",
				Title:     "No app icon configured",
				Detail:    "Neither expo.ios.icon nor expo.icon is set. An app icon is required.",
				Fix:       "Set \"icon\" in your app.json to a 1024x1024 PNG image path.",
				File:      "app.json",
			})
		}
		// Check: vague purpose strings in infoPlist
		if expo.IOS.InfoPlist != nil {
			vaguePurposeRe := regexp.MustCompile(`(?i)^(camera needed|location needed|microphone needed|photo access|access needed|needed|required|for the app|to function|for functionality)\.?$`)
			shortPurposeMinLen := 20 // Purpose strings should explain WHY, not just WHAT
			purposeKeys := []string{
				"NSCameraUsageDescription",
				"NSMicrophoneUsageDescription",
				"NSPhotoLibraryUsageDescription",
				"NSLocationWhenInUseUsageDescription",
				"NSLocationAlwaysUsageDescription",
				"NSUserTrackingUsageDescription",
				"NSFaceIDUsageDescription",
				"NSContactsUsageDescription",
				"NSCalendarsUsageDescription",
				"NSHealthShareUsageDescription",
				"NSBluetoothAlwaysUsageDescription",
				"NSMotionUsageDescription",
			}
			for _, key := range purposeKeys {
				if val, ok := expo.IOS.InfoPlist[key]; ok {
					if str, ok := val.(string); ok {
						if vaguePurposeRe.MatchString(str) || len(str) < shortPurposeMinLen {
							findings = append(findings, Finding{
								Source:    "metadata",
								Severity:  "WARN",
								Guideline: "5.1.1",
								Title:     "Vague permission purpose string: " + key,
								Detail:    "\"" + str + "\" is too vague. Apple requires specific, user-facing descriptions explaining why your app needs this permission.",
								Fix:       "Rewrite the purpose string to explain specifically why your app needs this permission and how the data will be used.",
								File:      "app.json",
							})
						}
					}
				}
			}
		}

	} else {
		findings = append(findings, Finding{
			Source:    "metadata",
			Severity:  "WARN",
			Guideline: "2.1",
			Title:     "No iOS configuration in app.json",
			Detail:    "expo.ios section is missing. iOS-specific settings are needed for App Store submission.",
			Fix:       "Add an \"ios\" section to your expo config with at least bundleIdentifier and icon.",
			File:      "app.json",
		})
	}

	return findings, meta
}

func checkInfoPlistLocal(data []byte, plistPath, projectPath string) ([]Finding, AppMeta) {
	var findings []Finding
	var meta AppMeta

	content := string(data)
	relPath, _ := filepath.Rel(projectPath, plistPath)

	// Extract app name
	nameRe := regexp.MustCompile(`CFBundleDisplayName</key>\s*<string>([^<]*)</string>`)
	if m := nameRe.FindStringSubmatch(content); len(m) > 1 {
		meta.AppName = m[1]
	}

	// Extract bundle ID
	bundleRe := regexp.MustCompile(`CFBundleIdentifier</key>\s*<string>([^<]*)</string>`)
	if m := bundleRe.FindStringSubmatch(content); len(m) > 1 {
		meta.BundleID = m[1]
	}

	// Extract version
	versionRe := regexp.MustCompile(`CFBundleShortVersionString</key>\s*<string>([^<]*)</string>`)
	if m := versionRe.FindStringSubmatch(content); len(m) > 1 {
		meta.Version = m[1]
	}

	// Check for missing CFBundleDisplayName
	if !strings.Contains(content, "CFBundleDisplayName") {
		findings = append(findings, Finding{
			Source:    "metadata",
			Severity:  "WARN",
			Guideline: "2.3",
			Title:     "CFBundleDisplayName missing from Info.plist",
			Detail:    "The display name shown under the app icon is not set.",
			Fix:       "Add CFBundleDisplayName to your Info.plist.",
			File:      relPath,
		})
	}

	// Check for empty or template values
	templateValues := []string{"$(PRODUCT_NAME)", "$(PRODUCT_BUNDLE_IDENTIFIER)", "YOUR_"}
	for _, tmpl := range templateValues {
		if strings.Contains(content, tmpl) {
			// This is fine for Xcode projects (build-time substitution)
			// Only flag if it looks like an unreplaced placeholder
			if strings.Contains(tmpl, "YOUR_") {
				findings = append(findings, Finding{
					Source:    "metadata",
					Severity:  "WARN",
					Guideline: "2.1",
					Title:     "Info.plist contains placeholder value: " + tmpl,
					Detail:    "Unreplaced template values will cause submission issues.",
					Fix:       "Replace placeholder values with actual configuration.",
					File:      relPath,
				})
			}
		}
	}

	// Check purpose strings quality
	purposeStrings := map[string]string{
		"NSCameraUsageDescription":            "Camera",
		"NSMicrophoneUsageDescription":        "Microphone",
		"NSPhotoLibraryUsageDescription":      "Photo Library",
		"NSLocationWhenInUseUsageDescription": "Location",
		"NSLocationAlwaysUsageDescription":    "Location (Always)",
		"NSUserTrackingUsageDescription":      "User Tracking",
		"NSFaceIDUsageDescription":            "Face ID",
		"NSContactsUsageDescription":          "Contacts",
		"NSCalendarsUsageDescription":         "Calendars",
		"NSHealthShareUsageDescription":       "HealthKit",
		"NSBluetoothAlwaysUsageDescription":   "Bluetooth",
	}

	for key, name := range purposeStrings {
		if strings.Contains(content, key) {
			emptyRe := regexp.MustCompile(key + `</key>\s*<string>\s*</string>`)
			if emptyRe.MatchString(content) {
				findings = append(findings, Finding{
					Source:    "metadata",
					Severity:  "CRITICAL",
					Guideline: "5.1.1",
					Title:     name + " purpose string is empty in Info.plist",
					Detail:    key + " is declared but has no description. Apple will reject this.",
					Fix:       "Add a specific, user-facing description for why your app needs " + name + " access.",
					File:      relPath,
				})
			}
		}
	}

	return findings, meta
}

func findInfoPlists(projectPath string) []string {
	var results []string
	skipDirs := map[string]bool{
		"node_modules": true, ".git": true, "Pods": true,
		"build": true, "dist": true, ".expo": true,
		"DerivedData": true, "vendor": true,
	}

	filepath.Walk(projectPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.ToLower(info.Name()) == "info.plist" {
			// Skip test/example plists
			rel, _ := filepath.Rel(projectPath, path)
			lower := strings.ToLower(rel)
			if !strings.Contains(lower, "test") && !strings.Contains(lower, "example") {
				results = append(results, path)
			}
		}
		return nil
	})

	return results
}

func checkPrivacyPolicy(projectPath string) []Finding {
	var findings []Finding

	// Check app.json for privacy policy
	appJSON := filepath.Join(projectPath, "app.json")
	if data, err := os.ReadFile(appJSON); err == nil {
		content := string(data)
		// Expo doesn't have a direct privacyPolicy field, but check for it in plugins or extra
		hasPrivacyURL := strings.Contains(content, "privacyPolicyUrl") ||
			strings.Contains(content, "privacy_policy") ||
			strings.Contains(content, "privacyUrl")

		if !hasPrivacyURL {
			findings = append(findings, Finding{
				Source:    "metadata",
				Severity:  "WARN",
				Guideline: "5.1.1",
				Title:     "No privacy policy URL found in project config",
				Detail:    "A privacy policy URL is required for App Store submission. It wasn't found in app.json. You'll need to set it in App Store Connect.",
				Fix:       "Create a privacy policy page and add the URL in App Store Connect → App Information.",
			})
		}
	}

	return findings
}
