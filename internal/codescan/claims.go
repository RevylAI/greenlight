package codescan

import (
	"regexp"
	"strings"
)

// Claims describes which flow-dependent features an app *claims* to implement,
// based on the same feature-detection patterns used by the static rules — but
// WITHOUT the anti-pattern suppression. A claim means "Apple will exercise this
// flow during review," which is exactly where static analysis goes blind: it can
// confirm a string like `deleteAccount` exists in source, never that the flow works.
type Claims struct {
	// Feature presence — the trigger patterns from the static rules.
	AccountCreation bool `json:"account_creation"`
	IAP             bool `json:"iap"`
	SocialLogin     bool `json:"social_login"`
	Subscription    bool `json:"subscription"`

	// Anti-pattern presence — the strings that cause the static scanner to
	// SUPPRESS the corresponding warning. When a feature is claimed AND its
	// anti-pattern code is present, static reports GREENLIT — and that is the
	// precise false-negative runtime validation exists to catch.
	HasDeleteAccountCode bool `json:"has_delete_account_code"`
	HasRestoreCode       bool `json:"has_restore_code"`
	HasSignInWithApple   bool `json:"has_sign_in_with_apple"`
	HasRenewalDisclosure bool `json:"has_renewal_disclosure"`
}

// These mirror the patterns/antiPatterns in rules.go for the four flow-dependent
// rules (account-no-delete, iap-no-restore, social-login-no-apple,
// subscription-no-renewal-disclosure). Kept in sync deliberately: the runtime
// tier re-checks exactly the flows static can only guess.
var (
	reAccountCreation = regexp.MustCompile(`(?i)(createAccount|signUp|register.*user|create.*account|auth\(\)\.createUser)`)
	reIAP             = regexp.MustCompile(`(?i)(SKPaymentQueue|StoreKit|Product\.purchase|purchaseProduct|expo-in-app-purchases|react-native-iap|RevenueCat)`)
	reSocialLogin     = regexp.MustCompile(`(?i)(google.*sign.*in|GIDSignIn|GoogleSignin|facebook.*login|FBSDKLoginManager|LoginManager\.logIn)`)
	reSubscription    = regexp.MustCompile(`(?i)(subscriptionPeriod|autoRenewable|Product\.SubscriptionInfo|SKProductSubscriptionPeriod|requestSubscription\s*\(|getSubscriptions\s*\(|purchasePackage|PurchasesPackage)`)

	reDeleteAccount = regexp.MustCompile(`(?i)(deleteAccount|delete.*account|remove.*account|account.*delet|close.*account|closeAccount|cancel.*account|delete.*my.*account|erase.*account)`)
	reRestore       = regexp.MustCompile(`(?i)(restoreCompletedTransactions|restore.*purchase|restorePurchase|customerInfo|syncPurchases)`)
	reSiwA          = regexp.MustCompile(`(?i)(ASAuthorizationAppleIDProvider|SignInWithApple|apple.*auth|appleAuth|expo-apple-authentication)`)
	// "renew" is deliberately case-SENSITIVE (lowercase) for the bare "auto-
	// renew(s)" form, unlike the rest of this file — see the matching comment
	// on subscription-no-renewal-disclosure's antiPatterns in rules.go. Without
	// it, this same regex also matched the camelCase trigger symbols
	// themselves (autoRenewable, autoRenewStatus, willAutoRenew), so merely
	// calling the subscription API set HasRenewalDisclosure true.
	reRenewalDisclosure = regexp.MustCompile(`[Aa]uto-?renews?\b|(?i:automatically renew|renews? automatically|renewed automatically)`)
)

// DetectClaims walks the project — reusing the scanner's file collection and
// language detection — and reports which flow-dependent features are present.
func DetectClaims(root string) (Claims, error) {
	s := &Scanner{root: root}
	files, err := s.collectFiles()
	if err != nil {
		return Claims{}, err
	}

	var c Claims
	for _, fc := range files {
		switch fc.Language {
		case "swift", "objc", "typescript", "javascript":
		default:
			continue // ignore plist/json config — claims live in source
		}
		content := strings.Join(fc.Lines, "\n")
		if reAccountCreation.MatchString(content) {
			c.AccountCreation = true
		}
		if reIAP.MatchString(content) {
			c.IAP = true
		}
		if reSocialLogin.MatchString(content) {
			c.SocialLogin = true
		}
		if reSubscription.MatchString(content) {
			c.Subscription = true
		}
		if reDeleteAccount.MatchString(content) {
			c.HasDeleteAccountCode = true
		}
		if reRestore.MatchString(content) {
			c.HasRestoreCode = true
		}
		if reSiwA.MatchString(content) {
			c.HasSignInWithApple = true
		}
		if reRenewalDisclosure.MatchString(content) {
			c.HasRenewalDisclosure = true
		}
	}
	return c, nil
}
