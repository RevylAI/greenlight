package codescan

import "testing"

// A guard proves a branch dead only when it IS the whole condition. Negated and
// compound conditions contain the guard while compiling on every modern
// deployment target, so reading them as dead switches off a CRITICAL.
func TestDeadGuardRequiresTheWholeCondition(t *testing.T) {
	r := ruleByID(t, "uiwebview-removed")

	live := []struct {
		name string
		cond string
	}{
		{"negated", `#if !(__IPHONE_OS_VERSION_MIN_REQUIRED < __IPHONE_9_0)`},
		{"negated without parens", `#if !__IPHONE_OS_VERSION_MIN_REQUIRED < __IPHONE_9_0`},
		{"or'd with a shipping flag", `#if defined(LEGACY_SHIM) || __IPHONE_OS_VERSION_MIN_REQUIRED < __IPHONE_9_0`},
		{"and'd with another condition", `#if TARGET_OS_IPHONE && __IPHONE_OS_VERSION_MIN_REQUIRED < __IPHONE_9_0`},
	}
	for _, tc := range live {
		fc := objcCtx(tc.cond,
			`    UIWebView *live = [[UIWebView alloc] initWithFrame:CGRectZero];`,
			`#endif`,
		)
		if got := r.Check(fc); len(got) == 0 {
			t.Errorf("%s: condition is not the guard, UIWebView must still be CRITICAL", tc.name)
		}
	}

	dead := []struct {
		name string
		cond string
	}{
		{"bare guard", `#if __IPHONE_OS_VERSION_MIN_REQUIRED < __IPHONE_9_0`},
		{"parenthesized guard", `#if (__IPHONE_OS_VERSION_MIN_REQUIRED < __IPHONE_9_0)`},
		{"guard with trailing comment", `#if __IPHONE_OS_VERSION_MIN_REQUIRED < __IPHONE_9_0 // legacy shim`},
	}
	for _, tc := range dead {
		fc := objcCtx(tc.cond,
			`    UIWebView *shim = [[UIWebView alloc] initWithFrame:CGRectZero];`,
			`#endif`,
		)
		if got := r.Check(fc); len(got) != 0 {
			t.Errorf("%s: guarded shim must stay suppressed, got %+v", tc.name, got)
		}
	}
}

// #ifndef GUARD selects the branch that compiles when the guard is false — the
// exact inverse of what suppression assumes.
func TestIfndefIsNotADeadGuard(t *testing.T) {
	r := ruleByID(t, "uiwebview-removed")

	fc := objcCtx(
		`#ifndef __IPHONE_OS_VERSION_MIN_REQUIRED < __IPHONE_9_0`,
		`    UIWebView *live = [[UIWebView alloc] init];`,
		`#endif`,
	)
	if got := r.Check(fc); len(got) == 0 {
		t.Error("#ifndef must not suppress — the guarded branch is the live one")
	}
}

// The plist key is the purpose string, not the prompt. Declaring it without
// calling requestTrackingAuthorization is the most common ATT rejection, so it
// must not satisfy the anti-pattern.
func TestATTPurposeStringIsNotProofOfPrompt(t *testing.T) {
	r := ruleByID(t, "missing-att")

	purposeOnly := csCtx(`plist.root.SetString("NSUserTrackingUsageDescription", "We personalize ads");`)
	if r.AntiPatternMatched(purposeOnly) {
		t.Error("NSUserTrackingUsageDescription alone must not count as an ATT implementation")
	}

	prompts := []FileContext{
		csCtx(`ATTrackingStatusBinding.RequestAuthorizationTracking(callback);`),
		swiftCtx(`ATTrackingManager.requestTrackingAuthorization { status in }`),
	}
	for _, fc := range prompts {
		if !r.AntiPatternMatched(fc) {
			t.Errorf("a real ATT prompt must still suppress 5.1.2: %q", fc.Lines[0])
		}
	}

	// End to end: an ad SDK plus a purpose string still reports 5.1.2.
	tracking := csCtx(`using AppsFlyerSDK;`)
	if got := r.Check(tracking); len(got) == 0 {
		t.Error("an advertising SDK must trigger the ATT rule")
	}
}

// \b fails whenever `user` is followed by a word character, which is most real
// signup identifiers — and every C# shape this scanner was extended to read.
func TestSignupMatchesCamelCaseIdentifiers(t *testing.T) {
	r := ruleByID(t, "account-no-delete")

	signup := []FileContext{
		csCtx(`await api.RegisterUserAsync(email, password);`),
		csCtx(`public Task RegisterUserWithEmail(string e, string p) {`),
		tsCtx(`api.registerUserWithEmail(e, p);`),
		tsCtx(`api.registerUser(e, p);`),
	}
	for _, fc := range signup {
		if got := r.Check(fc); len(got) == 0 {
			t.Errorf("signup entry point missed: %q", fc.Lines[0])
		}
	}

	// The false positive the boundary was added for must stay fixed.
	ua := FileContext{Path: "W.mm", RelPath: "W.mm", Language: "objc", Lines: []string{
		`  [[NSUserDefaults standardUserDefaults] registerDefaults:@{ @"UserAgent": ua }];`,
	}}
	if got := r.Check(ua); len(got) != 0 {
		t.Errorf("registerDefaults/UserAgent must still not read as signup, got %+v", got)
	}

	// DetectClaims shares the pattern; the runtime tier must still exercise the flow.
	if !reAccountCreation.MatchString(`await api.RegisterUserAsync(e, p);`) {
		t.Error("DetectClaims must see camelCase signup identifiers too")
	}
	if reAccountCreation.MatchString(`registerDefaults:@{ @"UserAgent": ua }`) {
		t.Error("DetectClaims must not read a user-agent override as signup")
	}
}

// Text that mentions Sign in with Apple in order to deny it — or a docs link, or
// a disabled flag — is not evidence the feature exists.
func TestSIWADenialIsNotEvidence(t *testing.T) {
	r := ruleByID(t, "social-login-no-apple")

	denied := []string{
		`export const banner = "Sign in with Apple coming soon!";`,
		`const APPLE_SIGNIN_ENABLED = false;`,
		`config = { appleSignIn: false, googleSignIn: true };`,
		`// see https://developer.apple.com/sign-in-with-apple/`,
		`const docs = "https://developer.apple.com/documentation/authenticationservices";`,
	}
	for _, line := range denied {
		if r.AntiPatternMatched(csCtx(line)) {
			t.Errorf("denial/reference must not count as SIWA evidence: %q", line)
		}
	}

	allowed := []string{
		`            "APPLE_SIGNIN_RESULT_CANCELED",`,
		`auth.appleSignIn();`,
		`showButton("Sign in with Apple");`,
		`var provider = new ASAuthorizationAppleIDProvider();`,
	}
	for _, line := range allowed {
		if !r.AntiPatternMatched(csCtx(line)) {
			t.Errorf("real SIWA evidence must still count: %q", line)
		}
	}

	// End to end: a Google login next to the "coming soon" banner still reports 4.8.
	fc := tsCtx(
		`export const banner = "Sign in with Apple coming soon!";`,
		`export function googleSignIn() { return auth.signInWithGoogle(); }`,
	)
	if r.AntiPatternMatched(fc) {
		t.Error("a file that only promises SIWA must not suppress 4.8")
	}
	if got := r.Check(fc); len(got) == 0 {
		t.Error("Google login without SIWA must be reported")
	}
}

// `apple.*auth` spanned the whole line, so any line naming Apple that also held
// "auth" anywhere disabled 4.8 project-wide.
func TestSIWAAppleAuthIsBounded(t *testing.T) {
	r := ruleByID(t, "social-login-no-apple")

	if r.AntiPatternMatched(csCtx(`var appleId = user.Id; var token = googleAuthToken;`)) {
		t.Error("an appleId and an unrelated auth token on one line must not count as SIWA")
	}
	for _, line := range []string{
		`AppleAuthManager.Initialize();`,
		`import { appleAuth } from '@invertase/react-native-apple-authentication';`,
	} {
		if !r.AntiPatternMatched(csCtx(line)) {
			t.Errorf("a real Apple auth SDK must still count: %q", line)
		}
	}
}

// An escaped quote left the naive scanner believing the rest of the line was
// inside a string, so the trailing comment survived and satisfied the very rule
// it contradicted.
func TestStripHandlesEscapedQuotes(t *testing.T) {
	got := stripCommentsMultiline([]string{
		`void G() { GoogleSignin.SignIn(); }`,
		`string s = "quote: \" end";  // TODO: implement Sign in with Apple`,
		`char q = '\'';              // and Sign in with Apple here too`,
		`string p = @"C:\path\to";   // verbatim: backslash is literal`,
	})
	for i, line := range got[1:] {
		if containsFold(line, "Sign in with Apple") || containsFold(line, "verbatim") {
			t.Errorf("line %d: comment survived escape handling: %q", i+1, line)
		}
	}
	if !containsFold(got[3], `C:\path\to`) {
		t.Errorf("verbatim string content was lost: %q", got[3])
	}

	r := ruleByID(t, "social-login-no-apple")
	fc := csCtx(
		`void G() { GoogleSignin.SignIn(); }`,
		`string s = "quote: \" end";  // TODO: implement Sign in with Apple`,
	)
	if r.AntiPatternMatched(fc) {
		t.Error("a comment reachable only through a broken escape must not suppress 4.8")
	}
	if got := r.Check(fc); len(got) == 0 {
		t.Error("Google login without SIWA must still be reported")
	}
}

// codeOnly rules blank string contents; the same escape bug would leak a
// literal's text into the match.
func TestStripStringsHandlesEscapes(t *testing.T) {
	got := stripStringsAndComments(`var s = "a \" UIWebView(b) c"; UIWebView *real;`)
	if containsFold(got, "UIWebView(") {
		t.Errorf("string content leaked past an escaped quote: %q", got)
	}
	if !containsFold(got, "UIWebView *real") {
		t.Errorf("code after the literal was lost: %q", got)
	}

	verbatim := stripStringsAndComments(`var p = @"say ""UIWebView()"" now"; int x;`)
	if containsFold(verbatim, "UIWebView(") {
		t.Errorf("verbatim string content leaked: %q", verbatim)
	}
	if !containsFold(verbatim, "int x") {
		t.Errorf("code after the verbatim literal was lost: %q", verbatim)
	}
}

func containsFold(s, sub string) bool {
	return len(s) >= len(sub) && indexFold(s, sub) >= 0
}

func indexFold(s, sub string) int {
	lower := func(b byte) byte {
		if b >= 'A' && b <= 'Z' {
			return b + 32
		}
		return b
	}
outer:
	for i := 0; i+len(sub) <= len(s); i++ {
		for j := 0; j < len(sub); j++ {
			if lower(s[i+j]) != lower(sub[j]) {
				continue outer
			}
		}
		return i
	}
	return -1
}
