package playscan

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// GradleInfo is what the policy rules need out of the Gradle build files.
type GradleInfo struct {
	TargetSDK int
	MinSDK    int
	// TargetSDKFile / TargetSDKLine locate the declaration so the report can
	// point at the line to edit.
	TargetSDKFile string
	TargetSDKLine int

	// BillingVersion is the Play Billing Library major version, 0 if absent.
	BillingVersion    int
	BillingVersionRaw string
	BillingFile       string
	BillingLine       int
	HasAdsSDK         bool
	HasAuthSDK        bool
	AdsSDKFile        string
	AdsSDKLine        int

	// HasAndroidPlugin is true when a build file actually configures Android.
	// A Gradle file alone proves nothing — plenty of pure-JVM Kotlin projects
	// have one — so this is what separates an Android project from any other
	// Gradle project.
	HasAndroidPlugin bool

	// Namespace is the application ID declared in Gradle, used when the
	// manifest omits the legacy package attribute.
	Namespace string
}

// Gradle DSL comes in Groovy and Kotlin flavours, and every one of these forms
// appears in real projects:
//
//	targetSdkVersion 34          targetSdk 34
//	targetSdkVersion(34)         targetSdk = 34
//	targetSdk.set(34)            targetSdkVersion = 34
//
// A value that is not an integer literal (e.g. `targetSdkVersion
// rootProject.ext.targetSdkVersion`) is skipped here and picked up from
// whichever file defines the literal, since ext blocks are scanned too.
var (
	reTargetSDK = regexp.MustCompile(`\btargetSdk(?:Version)?\b\s*(?:=|\.set\(|\()?\s*["']?(\d{1,2})["']?`)
	reMinSDK    = regexp.MustCompile(`\bminSdk(?:Version)?\b\s*(?:=|\.set\(|\()?\s*["']?(\d{1,2})["']?`)

	// Matches com.android.billingclient:billing:8.0.0 and the -ktx artifact,
	// including version catalog style quoting.
	reBilling = regexp.MustCompile(`com\.android\.billingclient:billing(?:-ktx)?:["']?v?(\d+)(?:\.(\d+))?`)

	// The billing artifact with its version supplied indirectly, which is how
	// most real builds declare it. Without these the version is unreadable and
	// the support-window check silently never fires:
	//
	//	implementation "com.android.billingclient:billing:$billingVersion"
	//	billing = { module = "com.android.billingclient:billing", version.ref = "billing" }
	reBillingInterp = regexp.MustCompile(`com\.android\.billingclient:billing(?:-ktx)?:\$\{?([A-Za-z_][A-Za-z0-9_.]*)\}?`)
	reBillingRef    = regexp.MustCompile(`com\.android\.billingclient:billing(?:-ktx)?["'].*version\.ref\s*=\s*["']([A-Za-z_][A-Za-z0-9_-]*)["']`)

	// A version string constant, e.g. billingVersion = "7.1.1" or a
	// [versions] entry in a catalog.
	reVersionString = regexp.MustCompile(`(?:^|\s)(?:const\s+)?(?:val|var|ext\.)?\s*([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*["']v?(\d+)(?:\.(\d+))?[^"']*["']`)

	reAdsSDK = regexp.MustCompile(`(?i)(com\.google\.android\.gms:play-services-ads|com\.google\.android\.ads|applovin|com\.facebook\.android:audience-network|com\.unity3d\.ads|ironsource|com\.mbridge|com\.vungle|adcolony|com\.chartboost)`)

	// Authentication SDKs, used as the signal that an app creates accounts.
	//
	// The artifact name must terminate at the match: play-services-auth is an
	// auth SDK, but play-services-auth-blockstore (credential backup) and
	// play-services-auth-api-phone (SMS retrieval) are not, and treating them
	// as one is a false positive on apps with no accounts at all.
	reAuthSDK = regexp.MustCompile(`(?i)(firebase-auth(?:-ktx)?["':]|play-services-auth(?:-ktx)?["':]|com\.auth0|supabase.*gotrue|supabase-kt.*auth|com\.okta|com\.amplifyframework:aws-auth|@react-native-google-signin|react-native-fbsdk)`)

	// Modern AGP moved the application ID out of the manifest, so the package
	// name usually lives in the Gradle files now.
	reNamespace = regexp.MustCompile(`\b(?:namespace|applicationId)\s*=?\s*["']([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+)["']`)

	// A targetSdk whose value is an expression rather than a literal. Real
	// projects reach the SDK level through a named constant far more often
	// than they inline it, in at least these shapes:
	//
	//	targetSdk target_sdk                                  (properties variable)
	//	targetSdk = ProjectConfig.Android.sdkTarget           (Kotlin object)
	//	targetSdk = project.property("targetSdkVersion") as Int
	//	targetSdk = libs.versions.targetSdk.get().toInt()
	//
	// Capturing the expression lets it be resolved against the symbols
	// collected from every other build file.
	reTargetSDKRef = regexp.MustCompile(`\btargetSdk(?:Version)?\b\s*(?:=|\.set\(|\()?\s*([A-Za-z_"'][^\n]*)`)

	// Integer constants a targetSdk expression can refer to, in the forms
	// Gradle, Kotlin DSL, and gradle.properties each use.
	reSymbolAssign = regexp.MustCompile(`(?:^|\s)(?:const\s+)?(?:val|var|ext\.)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\d{1,2})\s*$`)
	reSymbolSet    = regexp.MustCompile(`set\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']\s*,\s*(\d{1,2})\s*\)`)
	reSymbolTo     = regexp.MustCompile(`["']([A-Za-z_][A-Za-z0-9_]*)["']\s+to\s+(\d{1,2})\b`)

	// The identifier a targetSdk expression ultimately names: a quoted
	// property key if there is one, else the last segment of a dotted path.
	reQuotedIdent = regexp.MustCompile(`["']([A-Za-z_][A-Za-z0-9_]*)["']`)
	reDottedIdent = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)`)

	// Matches the Android Gradle plugin being applied, or an android {}
	// configuration block, in either Groovy or Kotlin DSL.
	reAndroidPlugin = regexp.MustCompile(`(com\.android\.(application|library)|\bandroid\s*\{|\bandroid\s*\(|AndroidApplicationConventionPlugin|com\.android\.tools\.build:gradle)`)
)

// isGradleFile reports whether a filename is a Gradle build script.
func isGradleFile(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".gradle") || strings.HasSuffix(lower, ".gradle.kts")
}

// isVersionCatalog reports whether a file is a Gradle version catalog, where
// modern projects keep the SDK levels and dependency versions the build
// scripts interpolate.
func isVersionCatalog(name string) bool {
	return strings.EqualFold(name, "libs.versions.toml")
}

// isConventionPlugin reports whether a path is a Kotlin convention plugin.
//
// Projects using build-logic or buildSrc set targetSdk in precompiled plugins
// rather than in any .gradle file, so without these the scan cannot resolve the
// value on a large share of modern Android repos.
func isConventionPlugin(path string) bool {
	if !strings.HasSuffix(strings.ToLower(path), ".kt") {
		return false
	}
	p := filepath.ToSlash(path)
	for _, dir := range conventionPluginDirs {
		if strings.Contains(p, dir) {
			return true
		}
	}
	return false
}

// conventionPluginDirs are the directory names projects use for precompiled
// build logic. There is no single convention, so each real variant seen in the
// wild is listed rather than guessed at.
var conventionPluginDirs = []string{
	"/build-logic/", "/buildSrc/", "/build-plugin/",
	"/build-conventions/", "/gradle/plugins/", "/build-logic-", "/buildlogic/",
}

// isGradleProperties reports whether a file is a gradle.properties, where many
// projects keep the SDK levels their build scripts interpolate.
func isGradleProperties(name string) bool {
	return strings.EqualFold(name, "gradle.properties")
}

// targetSdkIsNotTheApps reports whether a targetSdk assignment belongs to
// something other than the shipped application — the lint tool's target or the
// instrumentation test target. Reading those as the app's target would report a
// compliant app as non-compliant, or worse, the reverse.
func targetSdkIsNotTheApps(line string) bool {
	return strings.Contains(line, "lint.targetSdk") ||
		strings.Contains(line, "testOptions.targetSdk") ||
		strings.Contains(line, "lint {") ||
		strings.Contains(line, "targetSdkPreview")
}

// parseGradleFiles reads every Gradle script found and folds them into one view.
//
// Paths must be ordered most-specific-first (the app module before the root
// project), because a value already resolved from the app module wins: the app
// module's android {} block is what actually ships, and a root ext block only
// supplies the default it interpolates.
func parseGradleFiles(paths []string, relTo func(string) string) *GradleInfo {
	g := &GradleInfo{}

	// Integer constants seen anywhere in the build, used to resolve a
	// targetSdk that is expressed as a reference. First definition wins,
	// matching the most-authoritative-first file ordering.
	symbols := map[string]int{}
	// The first unresolved targetSdk expression, kept in case no literal turns up.
	var refExpr, refFile string
	var refLine int

	// Version strings, and the first unresolved billing version reference.
	versionStrings := map[string]string{}
	var billingRef, billingRefFile string
	var billingRefLine int

	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		rel := relTo(p)
		for i, line := range strings.Split(string(data), "\n") {
			lineNo := i + 1
			code := stripGradleComment(line)
			if code == "" {
				continue
			}

			if m := reVersionString.FindStringSubmatch(code); m != nil {
				if _, seen := versionStrings[m[1]]; !seen {
					v := m[2]
					if m[3] != "" {
						v = m[2] + "." + m[3]
					}
					versionStrings[m[1]] = v
				}
			}

			for _, re := range []*regexp.Regexp{reSymbolAssign, reSymbolSet, reSymbolTo} {
				if m := re.FindStringSubmatch(code); m != nil {
					if v, err := strconv.Atoi(m[2]); err == nil {
						if _, seen := symbols[m[1]]; !seen {
							symbols[m[1]] = v
						}
					}
				}
			}

			if g.TargetSDK == 0 && !targetSdkIsNotTheApps(code) {
				if m := reTargetSDK.FindStringSubmatch(code); m != nil {
					if v, err := strconv.Atoi(m[1]); err == nil {
						g.TargetSDK, g.TargetSDKFile, g.TargetSDKLine = v, rel, lineNo
					}
				} else if refExpr == "" {
					if m := reTargetSDKRef.FindStringSubmatch(code); m != nil {
						refExpr, refFile, refLine = m[1], rel, lineNo
					}
				}
			}
			if g.MinSDK == 0 {
				if m := reMinSDK.FindStringSubmatch(code); m != nil {
					if v, err := strconv.Atoi(m[1]); err == nil {
						g.MinSDK = v
					}
				}
			}
			if g.BillingVersion == 0 {
				if m := reBilling.FindStringSubmatch(code); m != nil {
					if v, err := strconv.Atoi(m[1]); err == nil {
						g.BillingVersion = v
						g.BillingVersionRaw = m[1]
						if m[2] != "" {
							g.BillingVersionRaw = m[1] + "." + m[2]
						}
						g.BillingFile, g.BillingLine = rel, lineNo
					}
				} else if billingRef == "" {
					if mm := reBillingInterp.FindStringSubmatch(code); mm != nil {
						billingRef, billingRefFile, billingRefLine = lastIdentSegment(mm[1]), rel, lineNo
					} else if mm := reBillingRef.FindStringSubmatch(code); mm != nil {
						billingRef, billingRefFile, billingRefLine = mm[1], rel, lineNo
					}
				}
			}
			if g.Namespace == "" {
				if m := reNamespace.FindStringSubmatch(code); m != nil {
					g.Namespace = m[1]
				}
			}
			if !g.HasAndroidPlugin && reAndroidPlugin.MatchString(code) {
				g.HasAndroidPlugin = true
			}
			if !g.HasAdsSDK && reAdsSDK.MatchString(code) {
				g.HasAdsSDK, g.AdsSDKFile, g.AdsSDKLine = true, rel, lineNo
			}
			if !g.HasAuthSDK && reAuthSDK.MatchString(code) {
				g.HasAuthSDK = true
			}
		}
	}

	if g.BillingVersion == 0 && billingRef != "" {
		if raw, ok := versionStrings[billingRef]; ok {
			if major, err := strconv.Atoi(strings.SplitN(raw, ".", 2)[0]); err == nil {
				g.BillingVersion, g.BillingVersionRaw = major, raw
				g.BillingFile, g.BillingLine = billingRefFile, billingRefLine
			}
		}
	}

	if g.TargetSDK == 0 && refExpr != "" {
		if v, ok := resolveSDKRef(refExpr, symbols); ok {
			g.TargetSDK, g.TargetSDKFile, g.TargetSDKLine = v, refFile, refLine
		}
	}
	return g
}

// lastIdentSegment returns the final segment of a dotted reference, e.g.
// "libs.versions.billing" -> "billing".
func lastIdentSegment(ref string) string {
	if i := strings.LastIndex(ref, "."); i >= 0 && i+1 < len(ref) {
		return ref[i+1:]
	}
	return ref
}

// resolveSDKRef resolves a targetSdk expression against the collected symbols.
//
// The name is taken from a quoted property key when the expression has one
// (project.property("targetSdkVersion")), otherwise from the last identifier
// in a dotted path (ProjectConfig.Android.sdkTarget -> sdkTarget). Values
// below API 14 are rejected: no shipping app targets them, so a match that low
// means the wrong symbol was resolved and reporting it would be worse than
// admitting the value is unknown.
func resolveSDKRef(expr string, symbols map[string]int) (int, bool) {
	var candidates []string
	if m := reQuotedIdent.FindStringSubmatch(expr); m != nil {
		candidates = append(candidates, m[1])
	}
	if idents := reDottedIdent.FindAllString(expr, -1); len(idents) > 0 {
		// Walk from the most specific segment outward.
		for i := len(idents) - 1; i >= 0; i-- {
			candidates = append(candidates, idents[i])
		}
	}
	for _, name := range candidates {
		if v, ok := symbols[name]; ok && v >= 14 {
			return v, true
		}
	}
	return 0, false
}

// stripGradleComment removes a trailing // comment and drops whole-line
// comments, so a commented-out dependency is not read as a live one. Block
// comments spanning lines are not tracked; a `/*` line is dropped wholesale,
// which errs toward skipping rather than inventing a match.
func stripGradleComment(line string) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") || strings.HasPrefix(trimmed, "/*") {
		return ""
	}
	if idx := strings.Index(trimmed, "//"); idx >= 0 {
		// Only strip when the // is not inside a quoted string, which is the
		// common case for URLs in maven { url "https://..." } lines.
		if !strings.Contains(trimmed[:idx], "\"") && !strings.Contains(trimmed[:idx], "'") {
			trimmed = strings.TrimSpace(trimmed[:idx])
		}
	}
	return trimmed
}
