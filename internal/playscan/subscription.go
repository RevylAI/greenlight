package playscan

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// subscriptionSourceExts are the Android app-source files worth reading for
// subscription signals. Kotlin and Java carry the billing call sites; XML
// (string resources and Compose-adjacent layout files some projects still
// ship) is where the required disclosure copy usually lives when it is not
// hardcoded directly in a Composable or Activity.
var subscriptionSourceExts = map[string]bool{
	".kt": true, ".kts": true, ".java": true, ".xml": true,
}

// reSubscriptionAPI matches subscription-specific Play Billing call sites.
// This is deliberately narrower than "ships Play Billing at all":
// com.android.billingclient:billing is also the dependency for pure one-time
// IAP, so a Gradle-only signal would false-positive on every app that never
// sells a subscription. ProductType.SUBS / SkuType.SUBS / querySubscriptions /
// SubscriptionOfferDetails only appear in code that actually queries or
// builds a subscription purchase flow.
//
// RevenueCat's purchasePackage/PurchasesPackage is deliberately NOT included
// here (it used to be, see reSubscriptionPackageCall below): RevenueCat uses
// the identical call for every package type, including LIFETIME and other
// one-time products, so the bare call site is not proof of a subscription.
var reSubscriptionAPI = regexp.MustCompile(`(?i)(BillingClient\.ProductType\.SUBS|ProductType\.SUBS|BillingClient\.SkuType\.SUBS|SkuType\.SUBS|SubscriptionOfferDetails|querySubscriptions\s*\()`)

// reSubscriptionPackageCall matches RevenueCat's generic package-purchase
// call. On its own this proves nothing about subscription vs. one-time/
// lifetime — it only counts as a subscription signal when paired with
// reSubscriptionPackageType finding a subscription-period package elsewhere
// in the same scanned source tree (see scanSubscriptionSource).
var reSubscriptionPackageCall = regexp.MustCompile(`(?i)(purchasePackage|PurchasesPackage)`)

// reSubscriptionPackageType matches a RevenueCat PackageType value that only
// exists for recurring subscriptions, never for LIFETIME/CUSTOM/UNKNOWN
// one-time packages. Paired with reSubscriptionPackageCall, this is the real
// subscription signal for RevenueCat integrations that never call the raw
// Play Billing SUBS APIs directly (RevenueCat's own SDK does that for them).
var reSubscriptionPackageType = regexp.MustCompile(`PackageType\.(ANNUAL|SIX_MONTH|THREE_MONTH|TWO_MONTH|MONTHLY|WEEKLY)\b`)

// reRenewalDisclosure matches the required Play Subscriptions policy wording
// ("automatic renewal terms"): the subscription renews unless the user
// cancels. Same wording shape as codescan's iOS §3.1.2 anti-pattern, since the
// disclosure requirement is the same user-facing sentence on either platform.
//
// "renew" is deliberately case-SENSITIVE (lowercase) for the bare
// "auto-renew(s/ing/al)" form, matching codescan's identical fix (899cef0)
// for the same bug shape: Play Billing's own `Purchase.isAutoRenewing()`
// field -- read routinely by any real subscription-status check, in the same
// file as reSubscriptionAPI's trigger symbols -- camelCases "Renewing" with
// a capital R, while real user-facing disclosure prose never does
// ("auto-renews unless cancelled", "automatically renew"). Under the old
// case-insensitive match, merely reading purchase.isAutoRenewing satisfied
// the anti-pattern and silently suppressed the Subscriptions finding
// project-wide, even with zero disclosure text anywhere. "auto" keeps
// optional capitalization for sentence-initial disclosure text
// ("Auto-renews unless..."). The suffix is "(s|ing|al)?" rather than a bare
// "s?\b" so real disclosure phrasing like "auto-renewing" and "auto-renewal"
// still counts -- a tighter "renews?\b" has no word boundary between "renew"
// and the "ing"/"al" that follows it in those words, so it silently stopped
// matching them (regressed by 57a1fd8, caught by Bugbot on this same PR).
var reRenewalDisclosure = regexp.MustCompile(`[Aa]uto-?renew(?:s|ing|al)?\b|(?i:automatically renew|renews? automatically|renewed automatically)`)

// subscriptionSignals is what the policy rule needs out of the app's Android
// source — both findable only by actually reading .kt/.java/.xml content,
// which nothing else in this package does (manifest and Gradle parsing only).
type subscriptionSignals struct {
	HasSubscriptionAPI bool
	File               string
	Line               int
	HasDisclosure      bool
}

// scanSubscriptionSource walks the Android source tree once, looking for a
// subscription-specific billing call site and, independently, the renewal
// disclosure wording anywhere in the project. A project with neither Kotlin,
// Java, nor XML files (an empty or non-Android scan root) comes back zero
// value, which callers treat as "nothing to report" rather than an error.
func scanSubscriptionSource(root string) subscriptionSignals {
	var sig subscriptionSignals
	// RevenueCat's purchasePackage call site only counts as a subscription
	// signal if a subscription-period PackageType also turns up somewhere in
	// the project -- neither one alone is proof (see reSubscriptionPackageCall
	// and reSubscriptionPackageType doc comments above). Both can land in
	// different files, so they can't be combined with the same early-stop
	// `errStop` shortcut the strong direct signal uses below.
	var hasPackageCall, hasPackageType bool
	var packageCallFile string
	var packageCallLine int
	errStop := errors.New("found both signals")

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !subscriptionSourceExts[strings.ToLower(filepath.Ext(d.Name()))] {
			return nil
		}
		// The manifest is already parsed elsewhere for its own purpose and
		// never contains billing call sites or disclosure prose, so reading
		// it again here would only cost time.
		if d.Name() == "AndroidManifest.xml" {
			return nil
		}

		lines, rerr := readSourceLines(path)
		if rerr != nil {
			return nil
		}
		relPath, _ := filepath.Rel(root, path)
		for i, line := range lines {
			if !sig.HasSubscriptionAPI && reSubscriptionAPI.MatchString(line) {
				sig.HasSubscriptionAPI = true
				sig.File = filepath.ToSlash(relPath)
				sig.Line = i + 1
			}
			if !hasPackageCall && reSubscriptionPackageCall.MatchString(line) {
				hasPackageCall = true
				packageCallFile = filepath.ToSlash(relPath)
				packageCallLine = i + 1
			}
			if !hasPackageType && reSubscriptionPackageType.MatchString(line) {
				hasPackageType = true
			}
			if !sig.HasDisclosure && reRenewalDisclosure.MatchString(line) {
				sig.HasDisclosure = true
			}
			if sig.HasSubscriptionAPI && sig.HasDisclosure {
				return errStop
			}
		}
		return nil
	})

	if !sig.HasSubscriptionAPI && hasPackageCall && hasPackageType {
		sig.HasSubscriptionAPI = true
		sig.File = packageCallFile
		sig.Line = packageCallLine
	}

	return sig
}

func readSourceLines(path string) ([]string, error) {
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
