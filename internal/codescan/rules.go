package codescan

import (
	"path/filepath"
	"regexp"
	"strings"
)

// AllRules returns every registered code scan rule.
func AllRules() []Rule {
	return []Rule{
		// CRITICAL - Immediate rejection
		&PatternRule{
			id:        "private-api",
			title:     "Private API usage detected",
			guideline: "2.5.1",
			severity:  SeverityCritical,
			detail:    "Using private/undocumented Apple APIs will cause immediate rejection.",
			fix:       "Replace with public API equivalents.",
			languages: []string{"swift", "objc"},
			patterns: []*regexp.Regexp{
				regexp.MustCompile(`NSSelectorFromString\s*\(\s*"_`),
				regexp.MustCompile(`performSelector.*"_`),
				regexp.MustCompile(`dlopen\s*\(`),
				regexp.MustCompile(`dlsym\s*\(`),
			},
		},
		&PatternRule{
			id:        "hardcoded-secrets",
			title:     "Hardcoded secret/API key detected",
			guideline: "1.6",
			severity:  SeverityCritical,
			detail:    "Hardcoded secrets in source code is a security vulnerability and review risk.",
			fix:       "Move secrets to environment variables or a secure keychain.",
			languages: []string{"swift", "objc", "typescript", "javascript"},
			patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(sk_live_|sk_test_|pk_live_|pk_test_)[a-zA-Z0-9]{20,}`),
				regexp.MustCompile(`(?i)(api[_-]?key|api[_-]?secret|secret[_-]?key)\s*[:=]\s*["'][a-zA-Z0-9]{20,}["']`),
				regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`),    // AWS access key
				regexp.MustCompile(`(?i)ghp_[a-zA-Z0-9]{36}`), // GitHub token
			},
		},
		&PatternRule{
			id:        "external-payment-digital",
			title:     "External payment for potentially digital goods",
			guideline: "3.1.1",
			severity:  SeverityCritical,
			detail:    "Using Stripe/PayPal/external payments for digital goods violates IAP requirements. Physical goods are OK.",
			fix:       "Use StoreKit/IAP for digital goods. External payment is only allowed for physical goods and services.",
			languages: []string{"swift", "objc", "typescript", "javascript"},
			patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)stripe.*payment.*intent`),
				regexp.MustCompile(`(?i)paypal.*checkout`),
				regexp.MustCompile(`(?i)braintree.*payment`),
				regexp.MustCompile(`(?i)checkout\.redirect.*url`),
			},
		},
		&PatternRule{
			id:        "crypto-mining",
			title:     "Cryptocurrency mining detected",
			guideline: "3.1.5",
			severity:  SeverityCritical,
			detail:    "On-device cryptocurrency mining is explicitly prohibited.",
			fix:       "Remove all mining functionality.",
			languages: []string{"swift", "objc", "typescript", "javascript"},
			patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(crypto|coin)\s*miner`),
				regexp.MustCompile(`(?i)hash\s*rate`),
				regexp.MustCompile(`(?i)mining\s*pool`),
				regexp.MustCompile(`(?i)stratum\+tcp`),
			},
		},
		&PatternRule{
			id:        "dynamic-code-exec",
			title:     "Dynamic code execution detected",
			guideline: "2.5.2",
			severity:  SeverityCritical,
			detail:    "Apps may not download, install, or execute code that changes app behavior.",
			fix:       "Remove dynamic code execution. Use native APIs instead.",
			languages: []string{"swift", "objc"},
			patterns: []*regexp.Regexp{
				regexp.MustCompile(`JSContext\s*\(\s*\).*evaluateScript`),
				regexp.MustCompile(`dlopen\s*\(`),
				regexp.MustCompile(`NSBundle.*load\b`),
			},
		},

		// HIGH - Likely rejection
		&PatternRule{
			id:        "missing-att",
			title:     "Ad/tracking SDK without ATT implementation",
			guideline: "5.1.2",
			severity:  SeverityWarn,
			detail:    "Using advertising or tracking SDKs requires App Tracking Transparency.",
			fix:       "Implement ATT prompt before any tracking. Add NSUserTrackingUsageDescription to Info.plist.",
			languages: []string{"swift", "objc", "typescript", "javascript"},
			patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(firebase.*analytics|google.*analytics|facebook.*sdk|fbsdk|adjust.*sdk|appsflyer|mixpanel)`),
				regexp.MustCompile(`(?i)(import\s+Amplitude|AmplitudeSwift|amplitude\.init|Amplitude\.instance|amplitude-js|@amplitude/)`),
				regexp.MustCompile(`(?i)(import.*@segment/|analytics-react-native|SegmentAnalytics|createClient.*writeKey)`),
			},
			antiPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(ATTrackingManager|requestTrackingAuthorization|AppTrackingTransparency|expo-tracking-transparency)`),
			},
			antiPatternsGlobal: true,
			firstMatchOnly:     true,
		},
		&PatternRule{
			id:        "social-login-no-apple",
			title:     "Social login without Sign in with Apple",
			guideline: "4.8",
			severity:  SeverityWarn,
			detail:    "Apps with third-party login (Google, Facebook, etc.) must also offer Sign in with Apple.",
			fix:       "Add Sign in with Apple as a login option alongside other social logins.",
			languages: []string{"swift", "objc", "typescript", "javascript"},
			patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(google.*sign.*in|GIDSignIn|GoogleSignin|facebook.*login|FBSDKLoginManager|LoginManager\.logIn)`),
			},
			antiPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(ASAuthorizationAppleIDProvider|SignInWithApple|apple.*auth|appleAuth|expo-apple-authentication)`),
			},
			antiPatternsGlobal: true,
			firstMatchOnly:     true,
		},
		&PatternRule{
			id:        "iap-no-restore",
			title:     "In-app purchases without restore functionality",
			guideline: "3.1.1",
			severity:  SeverityWarn,
			detail:    "Apps with IAP must include a 'Restore Purchases' button.",
			fix:       "Add a 'Restore Purchases' button that calls restoreCompletedTransactions or equivalent.",
			languages: []string{"swift", "objc", "typescript", "javascript"},
			patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(SKPaymentQueue|StoreKit|Product\.purchase|purchaseProduct|expo-in-app-purchases|react-native-iap|RevenueCat)`),
			},
			antiPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(restoreCompletedTransactions|restore.*purchase|restorePurchase|customerInfo|syncPurchases)`),
			},
			antiPatternsGlobal: true,
			firstMatchOnly:     true,
		},
		&PatternRule{
			id:        "account-no-delete",
			title:     "Account creation without account deletion",
			guideline: "5.1.1",
			severity:  SeverityWarn,
			detail:    "Apps that allow account creation must also offer account deletion functionality.",
			fix:       "Add an account deletion option in settings. Must actually delete data, not just deactivate.",
			languages: []string{"swift", "objc", "typescript", "javascript"},
			patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(createAccount|signUp|register.*user|create.*account|auth\(\)\.createUser)`),
			},
			antiPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(deleteAccount|delete.*account|remove.*account|account.*delet|close.*account|closeAccount|cancel.*account|delete.*my.*account|erase.*account)`),
			},
			antiPatternsGlobal: true,
			firstMatchOnly:     true,
		},

		// MEDIUM - May cause issues
		&PatternRule{
			id:        "platform-reference",
			title:     "Reference to competing platform",
			guideline: "2.3",
			severity:  SeverityWarn,
			detail:    "Mentioning other platforms (Android, Google Play, etc.) in user-facing strings may cause rejection.",
			fix:       "Remove references to competing platforms from all user-visible text.",
			languages: []string{"swift", "objc", "typescript", "javascript"},
			patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)"[^"]*\b(android|google\s*play|play\s*store|samsung|windows\s*phone)\b[^"]*"`),
				regexp.MustCompile(`(?i)'[^']*\b(android|google\s*play|play\s*store|samsung|windows\s*phone)\b[^']*'`),
				regexp.MustCompile("(?i)`[^`]*\\b(android|google\\s*play|play\\s*store|samsung|windows\\s*phone)\\b[^`]*`"),
				regexp.MustCompile(`(?i)\b(android|google\s*play|play\s*store|samsung|windows\s*phone)\b`), // bare text (JSX content)
			},
		},
		&PatternRule{
			id:        "placeholder-content",
			title:     "Placeholder content in user-facing strings",
			guideline: "2.1",
			severity:  SeverityWarn,
			detail:    "Placeholder text will cause rejection under App Completeness guidelines.",
			fix:       "Replace all placeholder text with final content.",
			languages: []string{"swift", "objc", "typescript", "javascript"},
			patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)"[^"]*\b(lorem ipsum|coming soon|under construction|todo|tbd)\b[^"]*"`),
				regexp.MustCompile(`(?i)'[^']*\b(lorem ipsum|coming soon|under construction|todo|tbd)\b[^']*'`),
				regexp.MustCompile("(?i)`[^`]*\\b(lorem ipsum|coming soon|under construction|todo|tbd)\\b[^`]*`"),
				regexp.MustCompile(`(?i)\b(lorem ipsum|coming soon|under construction|todo|tbd)\b`), // bare text (JSX content)
			},
			ignorePatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(func\s+placeholder\s*\(|\.placeholder\s*[:=]|placeholder\s*[:=]\s*[A-Z]|placeholder\s*\(in\s*context)`), // Swift/WidgetKit protocol methods and property assignments
			},
		},
		&PatternRule{
			id:        "console-log",
			title:     "Debug logging in production code",
			guideline: "2.1",
			severity:  SeverityInfo,
			detail:    "Excessive console.log/print statements may indicate the app is not production-ready.",
			fix:       "Remove or gate debug logging behind a DEBUG flag.",
			languages: []string{"typescript", "javascript"},
			patterns: []*regexp.Regexp{
				regexp.MustCompile(`console\.(log|debug|warn|error)\s*\(`),
			},
			countThreshold: 5, // Flag files with more than 5 log statements
		},
		&PatternRule{
			id:        "hardcoded-ipv4",
			title:     "Hardcoded IPv4 address",
			guideline: "2.5",
			severity:  SeverityWarn,
			detail:    "Apps must support IPv6. Hardcoded IPv4 addresses will fail on IPv6-only networks.",
			fix:       "Use hostnames instead of IP addresses. Ensure all networking supports IPv6.",
			languages: []string{"swift", "objc", "typescript", "javascript"},
			patterns: []*regexp.Regexp{
				regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`),
			},
			ignorePatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(version|0\.0\.0|127\.0\.0\.1|localhost)`), // ignore version strings and localhost
			},
		},
		&PatternRule{
			id:        "http-not-https",
			title:     "Insecure HTTP URL",
			guideline: "1.6",
			severity:  SeverityWarn,
			detail:    "App Transport Security requires HTTPS. HTTP URLs will be blocked by default.",
			fix:       "Use HTTPS for all network requests.",
			languages: []string{"swift", "objc", "typescript", "javascript"},
			patterns: []*regexp.Regexp{
				regexp.MustCompile(`"http://[^"]+"`),
				regexp.MustCompile(`'http://[^']+'`),
			},
			ignorePatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(localhost|127\.0\.0\.1|0\.0\.0\.0|http://example)`),
				regexp.MustCompile(`(?i)(w3\.org|xmlns|DTD|doctype)`), // XML/SVG namespace URIs and DTD references are identifiers, not network requests
			},
		},
		&PatternRule{
			id:        "webview-only",
			title:     "WebView-only app pattern detected",
			guideline: "4.2",
			severity:  SeverityWarn,
			detail:    "Apps that are primarily WebView wrappers may be rejected for minimum functionality.",
			fix:       "Add native features beyond just loading a web page.",
			languages: []string{"swift", "objc", "typescript", "javascript"},
			patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(WKWebView|UIWebView|WebView|react-native-webview).*loadRequest.*https?://`),
			},
		},
		&PatternRule{
			id:        "vague-purpose-string",
			title:     "Vague permission purpose string",
			guideline: "5.1.1",
			severity:  SeverityWarn,
			detail:    "Purpose strings must clearly explain why the app needs the permission. Vague strings get rejected.",
			fix:       "Write specific purpose strings: 'Take photos to attach to support tickets' NOT 'Camera access needed'.",
			languages: []string{"plist"},
			patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)<string>\s*(camera access|location access|microphone access|photo access|this app (needs|requires|uses))\s*</string>`),
				regexp.MustCompile(`(?i)<string>\s*(needed|required|for the app|to function|for functionality)\s*\.?\s*</string>`),
			},
		},
		&PlistKeyRule{
			id:        "missing-privacy-keys",
			title:     "Info.plist missing required privacy keys",
			guideline: "5.1.1",
			severity:  SeverityWarn,
		},
		&ExpoConfigRule{
			id: "expo-config-check",
		},
	}
}

// PatternRule matches regex patterns against file lines.
type PatternRule struct {
	id                 string
	title              string
	guideline          string
	severity           Severity
	detail             string
	fix                string
	languages          []string
	patterns           []*regexp.Regexp
	antiPatterns       []*regexp.Regexp // If found anywhere in project, suppress this rule
	antiPatternsGlobal bool             // Check anti-patterns across all files, not just current
	ignorePatterns     []*regexp.Regexp // Lines matching these are skipped
	countThreshold     int              // Only report if count exceeds this
	firstMatchOnly     bool             // Project-level fact: cap to one per file; scanner collapses to one per project
}

func (r *PatternRule) RuleID() string { return r.id }

func (r *PatternRule) HasGlobalAntiPatterns() bool {
	return r.antiPatternsGlobal && len(r.antiPatterns) > 0
}

func (r *PatternRule) AntiPatternMatched(fc FileContext) bool {
	for _, line := range fc.Lines {
		for _, ap := range r.antiPatterns {
			if ap.MatchString(line) {
				return true
			}
		}
	}
	return false
}

func (r *PatternRule) Applies(fc FileContext) bool {
	for _, lang := range r.languages {
		if fc.Language == lang {
			return true
		}
	}
	return false
}

func (r *PatternRule) Check(fc FileContext) []Finding {
	var findings []Finding

	for lineNum, line := range fc.Lines {
		// Skip comment lines
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		// Skip lines matching ignore patterns
		ignored := false
		for _, ip := range r.ignorePatterns {
			if ip.MatchString(line) {
				ignored = true
				break
			}
		}
		if ignored {
			continue
		}

		for _, pattern := range r.patterns {
			if pattern.MatchString(line) {
				findings = append(findings, Finding{
					Severity:  r.severity,
					Guideline: r.guideline,
					Title:     r.title,
					Detail:    r.detail,
					Fix:       r.fix,
					File:      fc.RelPath,
					Line:      lineNum + 1,
					Code:      strings.TrimSpace(line),
				})
				break // One finding per line per rule
			}
		}
	}

	if r.countThreshold > 0 && len(findings) <= r.countThreshold {
		return nil
	}

	// "Missing safeguard" rules describe a project-level fact (e.g. account
	// creation exists but deletion doesn't) — one finding is enough, not one per
	// matching line.
	if r.firstMatchOnly && len(findings) > 1 {
		findings = findings[:1]
	}

	return findings
}

// PlistKeyRule checks Info.plist for required privacy keys when certain frameworks are detected.
type PlistKeyRule struct {
	id        string
	title     string
	guideline string
	severity  Severity
}

func (r *PlistKeyRule) Applies(fc FileContext) bool {
	return fc.Language == "plist" && strings.HasSuffix(strings.ToLower(fc.RelPath), "info.plist")
}

func (r *PlistKeyRule) Check(fc FileContext) []Finding {
	content := strings.Join(fc.Lines, "\n")
	var findings []Finding

	requiredIfUsed := map[string]string{
		"NSCameraUsageDescription":            "Camera",
		"NSMicrophoneUsageDescription":        "Microphone",
		"NSPhotoLibraryUsageDescription":      "Photo Library",
		"NSLocationWhenInUseUsageDescription": "Location (When In Use)",
		"NSLocationAlwaysUsageDescription":    "Location (Always)",
		"NSBluetoothAlwaysUsageDescription":   "Bluetooth",
		"NSMotionUsageDescription":            "Motion/Accelerometer",
		"NSFaceIDUsageDescription":            "Face ID",
		"NSUserTrackingUsageDescription":      "App Tracking",
	}

	for key, name := range requiredIfUsed {
		if strings.Contains(content, key) {
			// Key exists, check if the value is not empty
			// Simple check: look for <key>KEY</key> followed by <string></string>
			emptyPattern := regexp.MustCompile(key + `</key>\s*<string>\s*</string>`)
			if emptyPattern.MatchString(content) {
				findings = append(findings, Finding{
					Severity:  SeverityWarn,
					Guideline: "5.1.1",
					Title:     name + " purpose string is empty",
					Detail:    "The " + key + " key exists but has no description.",
					Fix:       "Add a clear, specific description of why your app needs " + name + " access.",
					File:      fc.RelPath,
				})
			}
		}
	}

	return findings
}

// ExpoConfigRule checks Expo app.json / app.config for common issues.
type ExpoConfigRule struct {
	id string
}

func (r *ExpoConfigRule) Applies(fc FileContext) bool {
	base := strings.ToLower(strings.TrimSuffix(fc.RelPath, filepath.Ext(fc.RelPath)))
	return base == "app" || base == "app.config"
}

func (r *ExpoConfigRule) Check(fc FileContext) []Finding {
	content := strings.Join(fc.Lines, "\n")
	var findings []Finding

	// Check for missing bundle identifier
	if strings.Contains(content, `"expo"`) {
		if !strings.Contains(content, `"bundleIdentifier"`) {
			findings = append(findings, Finding{
				Severity:  SeverityWarn,
				Guideline: "2.1",
				Title:     "Missing iOS bundle identifier in Expo config",
				Detail:    "The expo.ios.bundleIdentifier is not set.",
				Fix:       "Add bundleIdentifier to the ios section of your app.json.",
				File:      fc.RelPath,
			})
		}

		// Check for missing icon
		if !strings.Contains(content, `"icon"`) {
			findings = append(findings, Finding{
				Severity:  SeverityWarn,
				Guideline: "2.3",
				Title:     "Missing app icon in Expo config",
				Detail:    "No icon field found in app.json.",
				Fix:       "Add an icon field pointing to a 1024x1024 PNG.",
				File:      fc.RelPath,
			})
		}

		// Check for placeholder names
		lower := strings.ToLower(content)
		if strings.Contains(lower, `"my app"`) || strings.Contains(lower, `"new app"`) || strings.Contains(lower, `"test app"`) {
			findings = append(findings, Finding{
				Severity:  SeverityWarn,
				Guideline: "2.1",
				Title:     "Placeholder app name detected",
				Detail:    "The app name looks like a placeholder.",
				Fix:       "Set a proper app name before submitting.",
				File:      fc.RelPath,
			})
		}
	}

	return findings
}
