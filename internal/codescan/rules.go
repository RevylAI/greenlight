package codescan

import (
	"path/filepath"
	"regexp"
	"strings"
)

// AllRules returns every registered code scan rule.
func AllRules() []Rule {
	rules := []Rule{
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
			severity:  SeverityHigh,
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
			severity:  SeverityHigh,
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
			severity:  SeverityHigh,
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
			id:        "subscription-no-renewal-disclosure",
			title:     "Auto-renewable subscription without renewal disclosure",
			guideline: "3.1.2",
			severity:  SeverityHigh,
			detail:    "Auto-renewable subscriptions must disclose, near the purchase button, that the subscription renews automatically unless cancelled, plus its price/period and a link to Terms of Use/Privacy Policy. This is the single most common 3.1.2 rejection and is distinct from the 3.1.1 restore-purchases requirement.",
			fix:       "Add subscription disclosure text next to the purchase button: title, length, price, and that it 'automatically renews unless cancelled', plus a visible link to your Terms of Use (EULA) and Privacy Policy.",
			languages: []string{"swift", "objc", "typescript", "javascript"},
			patterns: []*regexp.Regexp{
				// Subscription-specific SDK symbols, not generic one-time IAP
				// (that's iap-no-restore/§3.1.1) — auto-renewal disclosure is a
				// §3.1.2 requirement unique to recurring subscriptions.
				regexp.MustCompile(`(?i)(subscriptionPeriod|autoRenewable|Product\.SubscriptionInfo|SKProductSubscriptionPeriod)`),
				regexp.MustCompile(`(?i)(requestSubscription\s*\(|getSubscriptions\s*\()`),
				regexp.MustCompile(`(?i)(purchasePackage|PurchasesPackage)`),
			},
			antiPatterns: []*regexp.Regexp{
				// The required disclosure wording itself ("auto-renews unless
				// cancelled") — if it exists anywhere in the project, assume the
				// paywall actually shows it (same static-can-only-confirm-string-
				// presence caveat as account-no-delete/iap-no-restore below).
				//
				// "renew" is deliberately case-SENSITIVE (lowercase) here, unlike
				// the rest of this file: the camelCase StoreKit/RevenueCat symbols
				// this rule's own trigger patterns match (autoRenewable,
				// autoRenewStatus, willAutoRenew, ...) always capitalize the "Renew"
				// half, while real user-facing disclosure prose never does ("auto-
				// renews unless cancelled", "automatically renew"). Under the old
				// case-insensitive match, the trigger API names themselves
				// satisfied the anti-pattern, silently GREENLITing every app that
				// merely calls the subscription API without ever showing the
				// disclosure text. "auto" keeps optional capitalization for
				// sentence-initial disclosure text ("Auto-renews unless...").
				regexp.MustCompile(`[Aa]uto-?renews?\b|(?i:automatically renew|renews? automatically|renewed automatically)`),
			},
			antiPatternsGlobal: true,
			firstMatchOnly:     true,
		},
		&PatternRule{
			id:        "account-no-delete",
			title:     "Account creation without account deletion",
			guideline: "5.1.1",
			severity:  SeverityHigh,
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
			// Only flag the keyword inside a string/JSX literal — user-facing
			// copy is the §2.3 risk. A bare unquoted match flagged every React
			// Native app (Platform.OS checks, imports, package paths). This used
			// to be done with three '[^']*word[^']*'-shaped regexes, but those
			// have no notion of which quote opened which string: on a line with
			// two separate literals and a bare identifier between them (e.g.
			// `ios: 'Georgia', android: 'serif'`), the regex happily spans from
			// the first literal's closing quote to the second literal's opening
			// quote and "finds" the keyword in the gap between them, even though
			// neither literal contains it. literalPatterns instead extracts each
			// quoted literal's actual content first, so a bare object key named
			// "android" between two unrelated strings can never match.
			literalPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)\b(android|google\s*play|play\s*store|samsung|windows\s*phone)\b`),
			},
			ignorePatterns: []*regexp.Regexp{
				// Code constructs that legitimately contain these keywords but are
				// not user-facing copy: RN platform branches, imports/requires,
				// package names, file paths, and build config.
				regexp.MustCompile(`(?i)(Platform\.|import |require\(|from\s+['"][\w@./-]+['"]|@react-native|androidx|\.android\b|/android/|BuildConfig|\.gradle)`),
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
				// A single bare (unanchored) match against the whole line already
				// catches the keyword both inside a quoted literal and in bare JSX
				// text content — matchLine here is the raw line, not stripped of
				// string contents. The three '[^"]*word[^"]*"'-shaped variants that
				// used to sit alongside this were not just redundant: they have no
				// notion of which quote opened which string, so on a line with two
				// separate literals and a bare identifier between them (e.g.
				// `a: 'foo', todo: 'bar'`) they span from one literal's closing
				// quote to the next literal's opening quote and "find" the keyword
				// in the gap, even though neither literal contains it. Removing
				// them loses no real detection (the bare pattern already covers
				// every case they did) while removing that false-positive path.
				regexp.MustCompile(`(?i)\b(lorem ipsum|coming soon|under construction|todo|tbd)\b`),
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
				// Require valid 0-255 octets so version/build strings like
				// "2020.10.5.1" or "999.1.2.3" aren't mistaken for an IPv4 address.
				regexp.MustCompile(`\b(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}\b`),
			},
			ignorePatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(version|0\.0\.0|127\.0\.0\.1|localhost)`), // version strings and localhost (octet validation handles most others)
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
			id:        "uiwebview-removed",
			title:     "UIWebView is no longer accepted",
			guideline: "2.5.1",
			severity:  SeverityCritical,
			detail:    "Apple stopped accepting apps and updates that use the deprecated UIWebView API. Its presence is a hard rejection.",
			fix:       "Migrate to WKWebView.",
			languages: []string{"swift", "objc"},
			patterns: []*regexp.Regexp{
				// Require a real usage context (call, ObjC pointer, type position,
				// or the Delegate protocol). codeOnly below also blanks string
				// literals + comments so a textual mention can't trip this CRITICAL.
				regexp.MustCompile(`\bUIWebView\s*[(*]`), // UIWebView(  /  UIWebView *
				regexp.MustCompile(`\bUIWebViewDelegate\b`),
				regexp.MustCompile(`[:\[]\s*UIWebView\b`), // : UIWebView  /  [UIWebView
			},
			codeOnly: true,
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
		&ExportComplianceRule{
			id: "export-compliance",
		},
	}

	// Crypto apps carry App Review obligations (Guideline 3.1.5(b)) that a code
	// scan can detect but not verify — organization enrollment, exchange
	// licensing, a legal opinion. Append those advisories last.
	return append(rules, cryptoComplianceRules()...)
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
	literalPatterns    []*regexp.Regexp // Matched against each string literal's own content, not the raw line (see extractStringLiterals)
	antiPatterns       []*regexp.Regexp // If found anywhere in project, suppress this rule
	antiPatternsGlobal bool             // Check anti-patterns across all files, not just current
	ignorePatterns     []*regexp.Regexp // Lines matching these are skipped
	countThreshold     int              // Only report if count exceeds this
	firstMatchOnly     bool             // Project-level fact: cap to one per file; scanner collapses to one per project
	codeOnly           bool             // Strip string literals + comments before matching (for rules that must not fire on text)
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

		// codeOnly rules match against a copy with string literals and comments
		// blanked out, so a mention in text (e.g. "use UIWebView()") doesn't fire.
		matchLine := line
		if r.codeOnly {
			matchLine = stripStringsAndComments(line)
		}

		matched := false
		for _, pattern := range r.patterns {
			if pattern.MatchString(matchLine) {
				// Honor an inline `// greenlight:ignore <rule-id>` directive on the
				// matching line or the line directly above it.
				if suppressedByIgnore(fc.Lines, lineNum, r.id) {
					matched = true // still counts as "handled" so literalPatterns below doesn't re-fire
					break
				}
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
				matched = true
				break // One finding per line per rule
			}
		}

		// literalPatterns match against each string literal's actual extracted
		// content, not the raw line — see extractStringLiterals for why that
		// matters (a naive 'word' regex against the whole line can span across
		// two separate literals and match text that is in neither of them).
		if !matched && len(r.literalPatterns) > 0 {
		literalLoop:
			for _, lit := range extractStringLiterals(line) {
				for _, pattern := range r.literalPatterns {
					if pattern.MatchString(lit) {
						if suppressedByIgnore(fc.Lines, lineNum, r.id) {
							break literalLoop
						}
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
						break literalLoop // One finding per line per rule
					}
				}
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

// stripStringsAndComments blanks out the contents of "..."/'...' string literals
// and removes // line comments and /* */ block comments, so codeOnly rules match
// only real code. It's a lightweight scan (no escaped-quote handling), which is
// enough to keep call-shaped text like "UIWebView()" out of the match.
func stripStringsAndComments(line string) string {
	var b strings.Builder
	b.Grow(len(line))
	inStr := false
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		if inStr {
			b.WriteByte(' ')
			if c == quote {
				inStr = false
			}
			continue
		}
		switch {
		case c == '"' || c == '\'' || c == '`':
			inStr = true
			quote = c
			b.WriteByte(' ')
		case c == '/' && i+1 < len(line) && line[i+1] == '/':
			return b.String() // rest of the line is a comment
		case c == '/' && i+1 < len(line) && line[i+1] == '*':
			end := strings.Index(line[i+2:], "*/")
			if end < 0 {
				return b.String() // unterminated block comment
			}
			i += end + 3 // skip past the closing */
			b.WriteByte(' ')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// extractStringLiterals returns the content of each quoted string literal on
// the line — quote-type aware, like stripStringsAndComments, so a `"` inside
// a `'...'` literal (or vice versa) is just data, not a new boundary.
//
// This exists because a regex shaped like `'[^']*word[^']*'` has no notion of
// which quote opened which string: given `ios: 'Georgia', android: 'serif'`,
// it happily starts at the quote that *closes* 'Georgia', scans through the
// bare, unquoted ` android: ` text (not inside any string), and ends at the
// quote that *opens* 'serif' — "finding" the word "android" in the gap
// between two unrelated literals, even though neither literal contains it.
// Extracting each literal's real content first makes that cross-literal span
// impossible: "android" only ever matches if some actual literal is
// "android", "my android app", etc.
//
// A backslash-escaped quote (`\"`, `\'`, or an escaped backtick inside a JS
// template literal) does not end the literal — it's the same escaping every
// common source language uses for a literal quote character inside a string.
// Without honoring that, a quote preceded by `\` (e.g. the apostrophe in
// `'it\'s the android app'`) closed the literal early: everything after the
// escaped quote fell outside any literal and was silently dropped from the
// extracted content, so a real competitor mention after it was missed.
func extractStringLiterals(line string) []string {
	var literals []string
	var cur strings.Builder
	inStr := false
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		if inStr {
			if c == '\\' && i+1 < len(line) {
				// Keep the escaped character as literal content (not a
				// delimiter) and skip past it so it can't be mistaken for
				// the closing quote.
				cur.WriteByte(c)
				i++
				cur.WriteByte(line[i])
				continue
			}
			if c == quote {
				inStr = false
				literals = append(literals, cur.String())
				cur.Reset()
				continue
			}
			cur.WriteByte(c)
			continue
		}
		if c == '"' || c == '\'' || c == '`' {
			inStr = true
			quote = c
		}
	}
	return literals
}

// suppressedByIgnore reports whether the matching line, or the line directly
// above it, carries a `greenlight:ignore` directive. A bare directive suppresses
// every rule; `greenlight:ignore <rule-id>[ <rule-id>...]` suppresses only the
// listed rules.
func suppressedByIgnore(lines []string, lineNum int, ruleID string) bool {
	// A directive on this line (trailing or standalone) suppresses this line.
	if directiveSuppresses(lines[lineNum], ruleID) {
		return true
	}
	// The line above carries to this line only when it is a STANDALONE directive
	// comment — otherwise a trailing directive on a code line would also silence
	// a real finding on the next line.
	if lineNum > 0 {
		above := strings.TrimSpace(lines[lineNum-1])
		if isCommentLine(above) && directiveSuppresses(above, ruleID) {
			return true
		}
	}
	return false
}

func isCommentLine(trimmed string) bool {
	return strings.HasPrefix(trimmed, "//") ||
		strings.HasPrefix(trimmed, "/*") ||
		strings.HasPrefix(trimmed, "*") ||
		strings.HasPrefix(trimmed, "<!--")
}

// directiveSuppresses reports whether line carries a directive suppressing
// ruleID. The marker must be the first token of a comment (only whitespace
// between the comment opener and the marker) so prose that merely mentions
// "greenlight:ignore" is not a directive. A directive with no trailing tokens is
// "bare" and suppresses every rule; otherwise each whitespace/comma-separated
// token is matched against ruleID, so `greenlight:ignore <id> <reason>` works
// but `greenlight:ignore <reason>` (no id) does NOT blanket-suppress.
func directiveSuppresses(line, ruleID string) bool {
	const marker = "greenlight:ignore"
	i := strings.Index(line, marker)
	if i < 0 || !commentOpensJustBefore(line[:i]) {
		return false
	}
	rest := strings.TrimSpace(line[i+len(marker):])
	rest = strings.TrimLeft(rest, ":= \t")
	// Drop a trailing comment close so `/* greenlight:ignore */` and the XML
	// `<!-- greenlight:ignore -->` forms register as bare directives.
	rest = strings.TrimSpace(strings.TrimSuffix(rest, "-->"))
	rest = strings.TrimSpace(strings.TrimSuffix(rest, "*/"))
	if rest == "" {
		return true // bare directive: suppress every rule on the line
	}
	for _, tok := range strings.FieldsFunc(rest, func(r rune) bool {
		return r == ' ' || r == ',' || r == '\t'
	}) {
		if tok == ruleID {
			return true
		}
	}
	return false
}

// commentOpensJustBefore reports whether the text immediately preceding the
// marker is a comment opener followed only by whitespace.
func commentOpensJustBefore(before string) bool {
	t := strings.TrimRight(before, " \t")
	return strings.HasSuffix(t, "//") || strings.HasSuffix(t, "/*") || strings.HasSuffix(t, "<!--")
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

// expoKeyRE matches the unquoted `expo:` key used in app.config.js / app.config.ts
// (app.json uses the quoted "expo" form).
var expoKeyRE = regexp.MustCompile(`\bexpo\s*:`)

// ExportComplianceRule flags an Info.plist or Expo config that does not declare
// encryption export compliance. Without it, App Store Connect prompts for export
// compliance on every single upload.
type ExportComplianceRule struct {
	id string
}

func (r *ExportComplianceRule) Applies(fc FileContext) bool {
	if fc.Language == "plist" && strings.HasSuffix(strings.ToLower(fc.RelPath), "info.plist") {
		return true
	}
	// Match the Expo config files by exact name, not a trimmed basename — source
	// like App.tsx / app.js also collapses to "app" and would false-positive.
	switch strings.ToLower(filepath.Base(fc.RelPath)) {
	case "app.json", "app.config.js", "app.config.ts":
		return true
	}
	return false
}

func (r *ExportComplianceRule) Check(fc FileContext) []Finding {
	content := strings.Join(fc.Lines, "\n")
	// Already declared — Info.plist uses ITSAppUsesNonExemptEncryption; Expo
	// app.json uses ios.config.usesNonExemptEncryption.
	if strings.Contains(content, "ITSAppUsesNonExemptEncryption") ||
		strings.Contains(content, "usesNonExemptEncryption") {
		return nil
	}
	// For Expo configs, only flag a file that actually defines an app. app.json
	// uses the quoted "expo" key; app.config.js/ts use an unquoted `expo:`.
	if fc.Language != "plist" && !strings.Contains(content, `"expo"`) && !expoKeyRE.MatchString(content) {
		return nil
	}
	return []Finding{{
		Severity: SeverityInfo,
		Title:    "No encryption export-compliance declaration",
		Detail:   "Without an export-compliance declaration, App Store Connect asks about export compliance on every upload.",
		Fix:      "Set ITSAppUsesNonExemptEncryption in Info.plist (or ios.config.usesNonExemptEncryption in app.json): false if you only use exempt encryption like HTTPS, true (with documentation) otherwise.",
		File:     fc.RelPath,
	}}
}
