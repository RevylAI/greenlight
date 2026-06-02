package verify

import "github.com/RevylAI/greenlight/internal/codescan"

// Step is one block in a generated Revyl test.
type Step struct {
	Type         string // "instructions" | "validation" | "extraction"
	Desc         string
	VariableName string // for extraction steps only
}

// Flow is a flow-dependent App Store guideline. Static analysis can only confirm
// it by string presence; this tier re-checks it on a cloud device. Each flow maps
// to one codescan rule whose anti-pattern suppression is the false-negative risk.
type Flow struct {
	ID          string
	Guideline   string
	Title       string
	TestName    string // stable Revyl test name (idempotent create)
	StaticRule  string // the codescan rule id this corresponds to
	AntiPattern string // the source string that makes static PASS (for the message)
	Steps       []Step

	claimed      func(codescan.Claims) bool
	staticPassed func(codescan.Claims) bool
}

// Claimed reports whether the app claims this feature (so the flow is worth running).
func (f Flow) Claimed(c codescan.Claims) bool { return f.claimed(c) }

// StaticPassed reports whether the static scanner would have GREENLIT this flow —
// i.e. the anti-pattern code is present. Frames the "static said ship it" message.
func (f Flow) StaticPassed(c codescan.Claims) bool { return f.staticPassed(c) }

// AllFlows returns the runtime-verifiable flows, ordered by rejection impact.
func AllFlows() []Flow {
	return []Flow{
		{
			ID:           "account-deletion",
			Guideline:    "5.1.1",
			Title:        "Account deletion must actually delete the account",
			TestName:     "greenlight-account-deletion",
			StaticRule:   "account-no-delete",
			AntiPattern:  "deleteAccount",
			claimed:      func(c codescan.Claims) bool { return c.AccountCreation },
			staticPassed: func(c codescan.Claims) bool { return c.HasDeleteAccountCode },
			Steps: []Step{
				{Type: "instructions", Desc: "Log in with {{email}} and {{password}}"},
				{Type: "instructions", Desc: "Open the account or settings screen"},
				{Type: "instructions", Desc: "Tap 'Delete Account' and confirm any prompt to permanently delete the account"},
				{Type: "validation", Desc: "The app returns to a logged-out / sign-in screen after the deletion"},
				{Type: "validation", Desc: "Logging in again with {{email}} and {{password}} is rejected — the account no longer exists"},
			},
		},
		{
			ID:           "restore-purchases",
			Guideline:    "3.1.1",
			Title:        "Restore Purchases must trigger a real restore",
			TestName:     "greenlight-restore-purchases",
			StaticRule:   "iap-no-restore",
			AntiPattern:  "restorePurchases",
			claimed:      func(c codescan.Claims) bool { return c.IAP },
			staticPassed: func(c codescan.Claims) bool { return c.HasRestoreCode },
			Steps: []Step{
				{Type: "instructions", Desc: "Navigate to the paywall, store, or subscription settings screen"},
				{Type: "instructions", Desc: "Tap the 'Restore Purchases' button"},
				{Type: "validation", Desc: "Restore Purchases produces a visible response — a system restore prompt, a success or no-purchases message, or restored entitlements — and is not a silent no-op"},
			},
		},
		{
			ID:           "sign-in-apple",
			Guideline:    "4.8",
			Title:        "Sign in with Apple must actually start Apple sign-in",
			TestName:     "greenlight-sign-in-with-apple",
			StaticRule:   "social-login-no-apple",
			AntiPattern:  "Sign in with Apple",
			claimed:      func(c codescan.Claims) bool { return c.SocialLogin },
			staticPassed: func(c codescan.Claims) bool { return c.HasSignInWithApple },
			Steps: []Step{
				{Type: "instructions", Desc: "Go to the login screen"},
				{Type: "validation", Desc: "A 'Sign in with Apple' button is visible on the login screen"},
				{Type: "instructions", Desc: "Tap the 'Sign in with Apple' button"},
				{Type: "validation", Desc: "The native Apple sign-in sheet appears — the button is not a dead control"},
			},
		},
	}
}
