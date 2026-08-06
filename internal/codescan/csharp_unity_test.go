package codescan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func csCtx(lines ...string) FileContext {
	return FileContext{Path: "X.cs", RelPath: "X.cs", Lines: lines, Language: "csharp"}
}

func TestDetectLanguageCSharp(t *testing.T) {
	if got := detectLanguage("Assets/Scripts/Shop.cs"); got != "csharp" {
		t.Errorf("detectLanguage(.cs) = %q, want csharp", got)
	}
}

// Unity IAP usage (UnityEngine.Purchasing / IStoreListener) must trigger the
// iap-no-restore rule on C# sources, and Unity's restore path
// (IAppleExtensions.RestoreTransactions) must count as the anti-pattern.
func TestUnityIAPRule(t *testing.T) {
	r := ruleByID(t, "iap-no-restore")

	buy := csCtx(`public class ShopManager : MonoBehaviour, IStoreListener {`)
	if !r.Applies(buy) {
		t.Fatal("iap-no-restore should apply to csharp files")
	}
	if got := r.Check(buy); len(got) == 0 {
		t.Error("expected a finding for Unity IAP without restore")
	}

	restore := csCtx(`extensions.GetExtension<IAppleExtensions>().RestoreTransactions(OnRestore);`)
	if !r.AntiPatternMatched(restore) {
		t.Error("RestoreTransactions via IAppleExtensions should suppress iap-no-restore")
	}
}

// registerDefaults:@{@"UserAgent"...} — UIKit's user-agent override — must NOT
// count as account creation. Real signup entry points still must.
func TestAccountCreationUserAgentFalsePositive(t *testing.T) {
	r := ruleByID(t, "account-no-delete")

	fp := FileContext{Path: "W.mm", RelPath: "W.mm", Language: "objc", Lines: []string{
		`  [[NSUserDefaults standardUserDefaults] registerDefaults:@{ @"UserAgent": ua }];`,
	}}
	if got := r.Check(fp); len(got) != 0 {
		t.Errorf("registerDefaults/UserAgent must not read as account signup, got %+v", got)
	}

	real := []FileContext{
		csCtx(`public void RegisterUser(string email) {`),
		swiftCtx(`func createAccount(email: String) {`),
		csCtx(`authService.SignUp(email, password);`),
	}
	for i, ctx := range real {
		if got := r.Check(ctx); len(got) == 0 {
			t.Errorf("case %d: expected signup detection, got none", i)
		}
	}
}

// A file whose UIWebView usage sits behind a deployment-target guard
// (__IPHONE_OS_VERSION_MIN_REQUIRED < __IPHONE_9_0) never compiles into a
// modern binary and must not trip the CRITICAL uiwebview-removed rule.
func TestUIWebViewDeploymentGuardSuppression(t *testing.T) {
	r := ruleByID(t, "uiwebview-removed")

	guarded := objcCtx(
		`#if __IPHONE_OS_VERSION_MIN_REQUIRED < __IPHONE_9_0`,
		`        UIWebView *uiwebview = [[UIWebView alloc] initWithFrame:view.frame];`,
		`#endif`,
	)
	if got := r.Check(guarded); len(got) != 0 {
		t.Errorf("deployment-guarded UIWebView must be suppressed, got %+v", got)
	}

	live := objcCtx(`        UIWebView *uiwebview = [[UIWebView alloc] initWithFrame:view.frame];`)
	if got := r.Check(live); len(got) == 0 {
		t.Error("unguarded UIWebView usage must still be CRITICAL")
	}
}

// Suppression must cover the guarded branch ONLY. Skipping the whole file
// whenever the guard appears anywhere would hide shipping UIWebView usage that
// follows the #endif — a false negative on a hard-rejection rule, which is far
// worse than the false positive the guard handling exists to prevent.
func TestUIWebViewGuardSuppressionIsLineScoped(t *testing.T) {
	r := ruleByID(t, "uiwebview-removed")

	cases := []struct {
		name string
		fc   FileContext
	}{
		{"usage after #endif", objcCtx(
			`#if __IPHONE_OS_VERSION_MIN_REQUIRED < __IPHONE_9_0`,
			`  // legacy helper`,
			`#endif`,
			`  UIWebView *live = [[UIWebView alloc] init];`,
		)},
		{"usage in the #else branch", objcCtx(
			`#if __IPHONE_OS_VERSION_MIN_REQUIRED < __IPHONE_9_0`,
			`  WKWebView *modern = [[WKWebView alloc] init];`,
			`#else`,
			`  UIWebView *live = [[UIWebView alloc] init];`,
			`#endif`,
		)},
		{"usage before the guard", objcCtx(
			`  UIWebView *live = [[UIWebView alloc] init];`,
			`#if __IPHONE_OS_VERSION_MIN_REQUIRED < __IPHONE_9_0`,
			`#endif`,
		)},
		{"unbalanced directives suppress nothing", objcCtx(
			`#if __IPHONE_OS_VERSION_MIN_REQUIRED < __IPHONE_9_0`,
			`  UIWebView *live = [[UIWebView alloc] init];`,
		)},
	}
	for _, tc := range cases {
		if got := r.Check(tc.fc); len(got) == 0 {
			t.Errorf("%s: live UIWebView must still be reported", tc.name)
		}
	}

	// Nested conditionals inside the dead branch stay dead.
	nested := objcCtx(
		`#if __IPHONE_OS_VERSION_MIN_REQUIRED < __IPHONE_9_0`,
		`#ifdef DEBUG`,
		`  UIWebView *dead = [[UIWebView alloc] init];`,
		`#endif`,
		`#endif`,
	)
	if got := r.Check(nested); len(got) != 0 {
		t.Errorf("nested dead branch must stay suppressed, got %+v", got)
	}
}

// An anti-pattern asserts a feature is implemented. A comment saying the
// opposite must never satisfy it — otherwise a TODO disables the rule project
// -wide. String literals must still count: SDK-driven implementations name
// their providers in strings.
func TestAntiPatternIgnoresComments(t *testing.T) {
	r := ruleByID(t, "social-login-no-apple")

	denied := []FileContext{
		csCtx(`// TODO: Apple Sign In is not supported yet — planned for next sprint`),
		csCtx(`/* apple sign in: not implemented */`),
	}
	for _, fc := range denied {
		if r.AntiPatternMatched(fc) {
			t.Errorf("a comment must not count as SIWA evidence: %q", fc.Lines[0])
		}
	}

	allowed := []FileContext{
		csCtx(`            "APPLE_SIGNIN_RESULT_CANCELED",`),
		swiftCtx(`let provider = ASAuthorizationAppleIDProvider()`),
		csCtx(`auth.SignInWithApple(); // kick off the native sheet`),
	}
	for _, fc := range allowed {
		if !r.AntiPatternMatched(fc) {
			t.Errorf("real SIWA evidence must still count: %q", fc.Lines[0])
		}
	}
}

// stripComments must not mistake `//` inside a string literal for a comment.
func TestStripCommentsKeepsURLsInStrings(t *testing.T) {
	got := stripComments(`var url = "https://example.com/path"; // trailing note`)
	if !strings.Contains(got, "https://example.com/path") {
		t.Errorf("URL inside a string literal was clipped: %q", got)
	}
	if strings.Contains(got, "trailing note") {
		t.Errorf("trailing comment was not stripped: %q", got)
	}
}

// Unity's generated directories (Library alone often holds 100k+ files of
// engine cache) must be skipped — but only when the root actually is a Unity
// project, so a non-Unity repo with a Library/ folder keeps full coverage.
func TestUnityGeneratedDirs(t *testing.T) {
	unity := t.TempDir()
	if err := os.MkdirAll(filepath.Join(unity, "ProjectSettings"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(unity, "ProjectSettings", "ProjectSettings.asset"), []byte("m_EditorVersion: 6000.3.9f1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dirs := UnityGeneratedDirs(unity)
	if !dirs["Library"] || !dirs["Temp"] {
		t.Errorf("Unity project should skip Library/Temp, got %v", dirs)
	}

	if dirs := UnityGeneratedDirs(t.TempDir()); dirs != nil {
		t.Errorf("non-Unity project must not skip anything, got %v", dirs)
	}
}

// Platform SDKs abstract Sign in with Apple behind provider constants
// (APPLE_SIGNIN_RESULT_CANCELED, provider "apple-signin") without ever naming
// ASAuthorization*. Those must count as the SIWA anti-pattern, mirroring how
// google.*sign.*in counts as the Google-login trigger.
func TestSIWAViaProviderConstants(t *testing.T) {
	r := ruleByID(t, "social-login-no-apple")

	siwa := csCtx(`            "APPLE_SIGNIN_RESULT_CANCELED",`)
	if !r.AntiPatternMatched(siwa) {
		t.Error("APPLE_SIGNIN_* provider constant should count as Sign in with Apple")
	}

	unrelated := csCtx(`private const string PROVIDER_APPLE = "apple";`)
	if r.AntiPatternMatched(unrelated) {
		t.Error(`a bare "apple" provider constant alone should NOT count as SIWA`)
	}
}

// DetectClaims must see C# sources: Unity IAP claims the IAP flow, and a C#
// delete-account implementation counts as the delete anti-pattern.
func TestDetectClaimsCSharp(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("Shop.cs", "using UnityEngine.Purchasing;\nclass Shop : IStoreListener {}\n")
	write("Account.cs", "public void DeleteAccount() { api.Post(\"/account/delete\"); }\n")

	c, err := DetectClaims(dir)
	if err != nil {
		t.Fatalf("DetectClaims: %v", err)
	}
	if !c.IAP {
		t.Error("Unity IAP in C# should claim IAP")
	}
	if !c.HasDeleteAccountCode {
		t.Error("C# DeleteAccount should count as delete-account code")
	}
}
