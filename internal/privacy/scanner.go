package privacy

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Finding from privacy scan.
type Finding struct {
	Severity  string `json:"severity"`
	Guideline string `json:"guideline,omitempty"`
	Title     string `json:"title"`
	Detail    string `json:"detail"`
	Fix       string `json:"fix,omitempty"`
	File      string `json:"file,omitempty"`
	Line      int    `json:"line,omitempty"`
}

// RequiredReasonAPI represents an Apple Required Reason API category.
type RequiredReasonAPI struct {
	Name        string           // Human-readable name
	APIType     string           // NSPrivacyAccessedAPIType value
	Patterns    []*regexp.Regexp // Code patterns that indicate usage
	Languages   []string         // Languages to scan
	Description string           // What this API does
}

// ScanResult holds the full privacy scan output.
type ScanResult struct {
	ProjectPath    string    `json:"project_path"`
	HasPrivacyInfo bool      `json:"has_privacy_info"`
	DetectedAPIs   []string  `json:"detected_apis"`
	DeclaredAPIs   []string  `json:"declared_apis"`
	TrackingSDKs   []string  `json:"tracking_sdks,omitempty"`
	Findings       []Finding `json:"findings"`
}

var requiredReasonAPIs = []RequiredReasonAPI{
	{
		Name:    "File Timestamp",
		APIType: "NSPrivacyAccessedAPICategoryFileTimestamp",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(\.creationDate|\.modificationDate|\.contentModificationDate|fileModificationDate|URLResourceKey\.contentModification)`),
			regexp.MustCompile(`(?i)(NSFileCreationDate|NSFileModificationDate)`),
			regexp.MustCompile(`(?i)(\bstat\s*\(|\bfstat\s*\(|\blstat\s*\(|getattrlist)`),
		},
		Languages:   []string{"swift", "objc", "typescript", "javascript"},
		Description: "Accessing file timestamps (creation date, modification date)",
	},
	{
		Name:    "System Boot Time",
		APIType: "NSPrivacyAccessedAPICategorySystemBootTime",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(systemUptime|ProcessInfo.*uptime|mach_absolute_time)`),
			regexp.MustCompile(`(?i)(kern\.boottime|sysctl.*KERN_BOOTTIME)`),
		},
		Languages:   []string{"swift", "objc"},
		Description: "Accessing system boot time or uptime",
	},
	{
		Name:    "Disk Space",
		APIType: "NSPrivacyAccessedAPICategoryDiskSpace",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(volumeAvailableCapacity|volumeTotalCapacity|\.availableCapacity)`),
			regexp.MustCompile(`(?i)(NSFileSystemFreeSize|NSFileSystemSize|systemFreeSize)`),
			regexp.MustCompile(`(?i)(\bstatfs\s*\(|\bstatvfs\s*\()`),
		},
		Languages:   []string{"swift", "objc"},
		Description: "Querying disk space (available capacity, total capacity)",
	},
	{
		Name:    "Active Keyboards",
		APIType: "NSPrivacyAccessedAPICategoryActiveKeyboards",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(activeInputModes|UITextInputMode\.activeInputModes)`),
		},
		Languages:   []string{"swift", "objc"},
		Description: "Accessing the list of active keyboards",
	},
	{
		Name:    "User Defaults",
		APIType: "NSPrivacyAccessedAPICategoryUserDefaults",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(UserDefaults|NSUserDefaults)`),
			regexp.MustCompile(`(?i)(AsyncStorage|@react-native-async-storage)`),
		},
		Languages:   []string{"swift", "objc", "typescript", "javascript"},
		Description: "Reading/writing UserDefaults (includes React Native AsyncStorage)",
	},
}

// Known tracking/advertising SDKs
var trackingSDKPatterns = []struct {
	Pattern *regexp.Regexp
	Name    string
}{
	{regexp.MustCompile(`(?i)firebase.*analytics`), "Firebase Analytics"},
	{regexp.MustCompile(`(?i)google.*analytics`), "Google Analytics"},
	{regexp.MustCompile(`(?i)(fbsdk|facebook.*sdk)`), "Facebook SDK"},
	{regexp.MustCompile(`(?i)adjust.*sdk`), "Adjust SDK"},
	{regexp.MustCompile(`(?i)appsflyer`), "AppsFlyer"},
	{regexp.MustCompile(`(?i)(import\s+Amplitude|AmplitudeSwift|amplitude\.init|Amplitude\.instance|amplitude-js|@amplitude/)`), "Amplitude"},
	{regexp.MustCompile(`(?i)(mixpanel)`), "Mixpanel"},
	{regexp.MustCompile(`(?i)(@segment/|analytics-react-native)`), "Segment"},
	{regexp.MustCompile(`(?i)(branch\.io|react-native-branch)`), "Branch"},
	{regexp.MustCompile(`(?i)(google.*ads|GADMobileAds|admob)`), "Google Ads/AdMob"},
	{regexp.MustCompile(`(?i)(unity.*ads|UnityAds)`), "Unity Ads"},
	{regexp.MustCompile(`(?i)(applovin|AppLovinSDK)`), "AppLovin"},
	{regexp.MustCompile(`(?i)(ironSource|IronSource)`), "ironSource"},
}

// Scan runs the privacy analysis on a project directory.
func Scan(projectPath string) (*ScanResult, error) {
	result := &ScanResult{
		ProjectPath: projectPath,
	}

	// 1. Find PrivacyInfo.xcprivacy
	privacyInfoPath, privacyContent := findPrivacyManifest(projectPath)
	result.HasPrivacyInfo = privacyInfoPath != ""

	if result.HasPrivacyInfo {
		result.DeclaredAPIs = parsePrivacyManifest(privacyContent)
	} else {
		result.Findings = append(result.Findings, Finding{
			Severity:  "CRITICAL",
			Guideline: "5.1.1",
			Title:     "No PrivacyInfo.xcprivacy found in project",
			Detail:    "Privacy manifests are required since May 2024. Missing it triggers ITMS-91061.",
			Fix:       "Create a PrivacyInfo.xcprivacy file in your project. See: developer.apple.com/documentation/bundleresources/privacy-manifest-files",
		})
	}

	// 2. Scan code for Required Reason API usage
	detectedAPIs := make(map[string][]FileHit)
	trackingSDKsFound := make(map[string]bool)
	hasATT := false

	skipDirs := map[string]bool{
		"node_modules": true, ".git": true, "Pods": true,
		"build": true, "dist": true, ".expo": true,
		"DerivedData": true, "vendor": true,
	}

	filepath.Walk(projectPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			if info != nil && info.IsDir() && skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		lang := detectLang(path)
		if lang == "" {
			return nil
		}

		relPath, _ := filepath.Rel(projectPath, path)
		lines, err := readFileLines(path)
		if err != nil {
			return nil
		}

		fullContent := strings.Join(lines, "\n")

		// Check for ATT implementation
		if regexp.MustCompile(`(?i)(ATTrackingManager|requestTrackingAuthorization|AppTrackingTransparency|expo-tracking-transparency)`).MatchString(fullContent) {
			hasATT = true
		}

		// Check for tracking SDKs
		for _, sdk := range trackingSDKPatterns {
			if sdk.Pattern.MatchString(fullContent) {
				trackingSDKsFound[sdk.Name] = true
			}
		}

		// Check for Required Reason API usage
		for _, api := range requiredReasonAPIs {
			if !langMatch(lang, api.Languages) {
				continue
			}
			for lineNum, line := range lines {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
					continue
				}
				for _, p := range api.Patterns {
					if p.MatchString(line) {
						detectedAPIs[api.APIType] = append(detectedAPIs[api.APIType], FileHit{
							File: relPath,
							Line: lineNum + 1,
							Code: strings.TrimSpace(line),
							API:  api.Name,
						})
						break
					}
				}
			}
		}

		return nil
	})

	// 3. Cross-reference detected vs declared
	for apiType, hits := range detectedAPIs {
		apiName := hits[0].API
		result.DetectedAPIs = append(result.DetectedAPIs, apiName)

		declared := false
		for _, d := range result.DeclaredAPIs {
			if d == apiType {
				declared = true
				break
			}
		}

		if !declared && result.HasPrivacyInfo {
			result.Findings = append(result.Findings, Finding{
				Severity:  "CRITICAL",
				Guideline: "5.1.1",
				Title:     "Required Reason API used but not declared: " + apiName,
				Detail:    apiType + " usage detected in code but not in PrivacyInfo.xcprivacy. Found in " + formatHits(hits),
				Fix:       "Add " + apiType + " to NSPrivacyAccessedAPITypes in your PrivacyInfo.xcprivacy with the appropriate reason.",
			})
		} else if !declared && !result.HasPrivacyInfo {
			result.Findings = append(result.Findings, Finding{
				Severity:  "CRITICAL",
				Guideline: "5.1.1",
				Title:     "Required Reason API used without privacy manifest: " + apiName,
				Detail:    apiType + " detected in code. Found in " + formatHits(hits),
				Fix:       "Create PrivacyInfo.xcprivacy and declare " + apiType + " with the appropriate reason.",
			})
		}
	}

	// 4. Check tracking SDKs vs ATT
	for sdk := range trackingSDKsFound {
		result.TrackingSDKs = append(result.TrackingSDKs, sdk)
	}

	if len(trackingSDKsFound) > 0 && !hasATT {
		sdkList := strings.Join(result.TrackingSDKs, ", ")
		result.Findings = append(result.Findings, Finding{
			Severity:  "CRITICAL",
			Guideline: "5.1.2",
			Title:     "Tracking SDKs detected without ATT implementation",
			Detail:    "Found: " + sdkList + ". App Tracking Transparency prompt is required before any tracking.",
			Fix:       "Import AppTrackingTransparency and call requestTrackingAuthorization() before initializing any tracking SDK.",
		})
	}

	// 5. Check if privacy manifest declares tracking but no tracking SDKs found
	if result.HasPrivacyInfo && strings.Contains(privacyContent, "NSPrivacyTracking") && strings.Contains(privacyContent, "<true/>") && len(trackingSDKsFound) == 0 {
		result.Findings = append(result.Findings, Finding{
			Severity: "INFO",
			Title:    "Privacy manifest declares tracking but no tracking SDKs detected",
			Detail:   "NSPrivacyTracking is set to true but no known tracking SDKs were found in code.",
			Fix:      "Verify if your app actually tracks users. If not, set NSPrivacyTracking to false.",
		})
	}

	return result, nil
}

type FileHit struct {
	File string
	Line int
	Code string
	API  string
}

func formatHits(hits []FileHit) string {
	if len(hits) == 0 {
		return ""
	}
	if len(hits) == 1 {
		return hits[0].File + ":" + strings.TrimSpace(hits[0].Code)
	}
	// Show first 3
	var parts []string
	limit := 3
	if len(hits) < limit {
		limit = len(hits)
	}
	for _, h := range hits[:limit] {
		parts = append(parts, h.File)
	}
	s := strings.Join(parts, ", ")
	if len(hits) > 3 {
		s += fmt.Sprintf(" and %d more", len(hits)-3)
	}
	return s
}

func findPrivacyManifest(root string) (string, string) {
	var found string
	var content string

	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			if info != nil && info.IsDir() {
				name := info.Name()
				if name == "node_modules" || name == ".git" || name == "Pods" || name == "build" || name == "DerivedData" {
					return filepath.SkipDir
				}
			}
			return nil
		}

		if strings.ToLower(info.Name()) == "privacyinfo.xcprivacy" {
			found = path
			data, _ := os.ReadFile(path)
			content = string(data)
			return filepath.SkipAll
		}
		return nil
	})

	return found, content
}

func parsePrivacyManifest(content string) []string {
	var apis []string
	// Extract NSPrivacyAccessedAPIType values
	re := regexp.MustCompile(`NSPrivacyAccessedAPICategory\w+`)
	matches := re.FindAllString(content, -1)
	for _, m := range matches {
		apis = append(apis, m)
	}
	return apis
}

func detectLang(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".swift":
		return "swift"
	case ".m", ".h":
		return "objc"
	case ".ts", ".tsx":
		return "typescript"
	case ".js", ".jsx":
		return "javascript"
	}
	return ""
}

func langMatch(lang string, languages []string) bool {
	for _, l := range languages {
		if l == lang {
			return true
		}
	}
	return false
}

func readFileLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}
