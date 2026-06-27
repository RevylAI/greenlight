package codescan

import "testing"

func ruleByID(t *testing.T, id string) *PatternRule {
	t.Helper()
	for _, r := range AllRules() {
		if pr, ok := r.(*PatternRule); ok && pr.id == id {
			return pr
		}
	}
	t.Fatalf("rule %q not found", id)
	return nil
}

func swiftCtx(lines ...string) FileContext {
	return FileContext{Path: "X.swift", RelPath: "X.swift", Lines: lines, Language: "swift"}
}

func tsCtx(lines ...string) FileContext {
	return FileContext{Path: "X.ts", RelPath: "X.ts", Lines: lines, Language: "typescript"}
}

// An inline `// greenlight:ignore` directive (bare or rule-specific), on the
// matching line or the line directly above it, suppresses the finding.
func TestInlineIgnoreDirective(t *testing.T) {
	r := ruleByID(t, "hardcoded-ipv4")

	suppressed := []FileContext{
		swiftCtx(`let host = "10.1.2.3" // greenlight:ignore`),                   // bare, same line
		swiftCtx(`let host = "10.1.2.3" // greenlight:ignore hardcoded-ipv4`),    // rule-specific, same line
		swiftCtx(`// greenlight:ignore hardcoded-ipv4`, `let host = "10.1.2.3"`), // directive on line above
		swiftCtx(`/* greenlight:ignore */`, `let host = "10.1.2.3"`),             // block-comment bare
	}
	for i, ctx := range suppressed {
		if got := r.Check(ctx); len(got) != 0 {
			t.Errorf("case %d: expected suppression, got %d findings: %+v", i, len(got), got)
		}
	}

	// A directive naming a different rule must NOT suppress this one; and with no
	// directive the rule still fires.
	if got := r.Check(swiftCtx(`let host = "10.1.2.3" // greenlight:ignore some-other-rule`)); len(got) == 0 {
		t.Error("a directive for a different rule should not suppress this finding")
	}
	if got := r.Check(swiftCtx(`let host = "10.1.2.3"`)); len(got) == 0 {
		t.Error("expected a finding when no ignore directive is present")
	}

	// A TRAILING directive on a code line must suppress only its own line, not a
	// real finding on the line below.
	leak := swiftCtx(
		`let a = "10.1.2.3" // greenlight:ignore hardcoded-ipv4`,
		`let b = "192.168.5.5"`,
	)
	if got := r.Check(leak); len(got) != 1 {
		t.Errorf("trailing directive must not leak to the next line; want 1 finding, got %d: %+v", len(got), got)
	}

	// A prose comment that merely mentions the marker is not a directive.
	prose := swiftCtx(
		`// To silence this, add greenlight:ignore`,
		`let host = "10.1.2.3"`,
	)
	if got := r.Check(prose); len(got) != 1 {
		t.Errorf("prose mentioning the marker must not suppress; want 1 finding, got %d: %+v", len(got), got)
	}
}

// §2.5 hardcoded-ipv4 must flag genuine IPv4 literals but not 4-part
// version/build strings, which were previously misread as addresses.
func TestHardcodedIPv4IgnoresVersionStrings(t *testing.T) {
	r := ruleByID(t, "hardcoded-ipv4")

	clean := tsCtx(
		`const sdkVersion = "8.4.1.2"`, // version keyword guard
		`const build = "2020.10.5.1"`,  // 2020 is not a valid octet
		`const x = "999.1.2.3"`,        // 999 is not a valid octet
		`const local = "127.0.0.1"`,    // loopback ignored
	)
	if got := r.Check(clean); len(got) != 0 {
		t.Errorf("expected no findings for version/invalid/loopback, got %d: %+v", len(got), got)
	}

	dirty := tsCtx(
		`const host = "192.168.1.42"`,
		`const sdkEndpoint = "172.16.0.4"`, // real IP in an sdk-named var must NOT be ignored
	)
	if got := r.Check(dirty); len(got) != 2 {
		t.Errorf("expected 2 findings for real hardcoded IPv4 addresses, got %d: %+v", len(got), got)
	}
}

// §2.3 platform-reference must flag competitor mentions in user-facing copy but
// not React Native platform branches or imports — a bare unquoted match used to
// fire on virtually every RN app.
func TestPlatformReferenceIgnoresCodeConstructs(t *testing.T) {
	r := ruleByID(t, "platform-reference")

	clean := tsCtx(
		`if (Platform.OS === 'android') { doThing() }`,
		`const styles = Platform.select({ android: {}, ios: {} })`,
		`import Foo from 'react-native-android-foo'`,
		`} from '@react-native-community/android'`,
	)
	if got := r.Check(clean); len(got) != 0 {
		t.Errorf("expected no findings for RN platform code, got %d: %+v", len(got), got)
	}

	dirty := tsCtx(
		`const msg = "Also available on the Google Play store"`,
		`const cta = "Download from 'Google Play'"`, // "from '" inside copy must NOT be ignored
	)
	if got := r.Check(dirty); len(got) != 2 {
		t.Errorf("expected 2 findings for competitor mentions, got %d: %+v", len(got), got)
	}
}

// The flow-dependent guidelines static analysis can only weakly assert (missing
// account deletion, Sign in with Apple, restore purchases, ATT) are HIGH — likely
// rejections — not WARN. Mislabeling them WARN let apps that Apple rejects still
// read as GREENLIT; this test pins them at HIGH.
func TestHardRejectionRulesAreHigh(t *testing.T) {
	for _, id := range []string{"missing-att", "social-login-no-apple", "iap-no-restore", "account-no-delete"} {
		if r := ruleByID(t, id); r.severity != SeverityHigh {
			t.Errorf("rule %q: severity = %v, want HIGH", id, r.severity)
		}
	}
}

// A HIGH finding is tallied separately so the headline can show NEEDS REVIEW,
// but Passed stays "no criticals" for backward compatibility.
func TestComputeSummaryHigh(t *testing.T) {
	s := ComputeSummary([]Finding{
		{Severity: SeverityHigh},
		{Severity: SeverityHigh},
		{Severity: SeverityWarn},
		{Severity: SeverityInfo},
	}, 0)
	if s.High != 2 || s.Warns != 1 || s.Infos != 1 || s.Critical != 0 {
		t.Errorf("unexpected counts: %+v", s)
	}
	if !s.Passed {
		t.Error("Passed should stay true with no criticals (High is surfaced separately)")
	}
}

// Severity serializes as its name, so inserting a tier never shifts the wire
// value for JSON consumers reading codescan output.
func TestSeverityMarshalsAsName(t *testing.T) {
	b, err := SeverityHigh.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `"HIGH"` {
		t.Errorf("MarshalJSON = %s, want %q", b, `"HIGH"`)
	}
}

// UIWebView is a removed API and a hard rejection; the rule must flag it (and
// UIWebViewDelegate) as CRITICAL but not WKWebView or custom-named types.
func TestUIWebViewRemoved(t *testing.T) {
	r := ruleByID(t, "uiwebview-removed")

	for _, line := range []string{`let w = UIWebView()`, `class C: UIWebViewDelegate {}`, `UIWebView *w = [UIWebView new];`} {
		got := r.Check(swiftCtx(line))
		if len(got) == 0 {
			t.Errorf("expected a finding for %q", line)
		} else if got[0].Severity != SeverityCritical {
			t.Errorf("%q: severity = %v, want CRITICAL", line, got[0].Severity)
		}
	}
	negatives := []string{
		`let w = WKWebView()`,
		`let x = MyUIWebView()`,
		`let y = MyUIWebViewWrapper()`,
		`let s = "UIWebView"`,                              // string literal, not usage
		`logEvent("UIWebView_fallback_shown")`,             // identifier inside a string
		`let w = WKWebView() // migrated from UIWebView`,   // trailing-comment mention
		`let message = "Remove UIWebView() from old docs"`, // call-shaped text in a string
		`let web = WKWebView() // TODO remove UIWebView()`, // call-shaped text in a comment
	}
	for _, line := range negatives {
		if got := r.Check(swiftCtx(line)); len(got) != 0 {
			t.Errorf("did not expect a finding for %q, got %+v", line, got)
		}
	}
}

// Export-compliance: flag an Info.plist / Expo config that doesn't declare it,
// but stay quiet once it's declared or for non-Expo json.
func TestExportCompliance(t *testing.T) {
	r := &ExportComplianceRule{id: "export-compliance"}

	// Applies: Info.plist and the Expo config files, but NOT App.tsx / app.js source.
	if !r.Applies(FileContext{RelPath: "ios/App/Info.plist", Language: "plist"}) {
		t.Error("should apply to Info.plist")
	}
	if !r.Applies(FileContext{RelPath: "app.config.ts", Language: "typescript"}) {
		t.Error("should apply to app.config.ts")
	}
	if r.Applies(FileContext{RelPath: "App.tsx", Language: "typescript"}) {
		t.Error("must NOT apply to App.tsx source")
	}
	if r.Applies(FileContext{RelPath: "src/app.js", Language: "javascript"}) {
		t.Error("must NOT apply to app.js source")
	}

	infoNoKey := FileContext{RelPath: "Info.plist", Language: "plist", Lines: []string{"<key>CFBundleName</key><string>X</string>"}}
	if !r.Applies(infoNoKey) {
		t.Fatal("rule should apply to Info.plist")
	}
	if got := r.Check(infoNoKey); len(got) == 0 || got[0].Severity != SeverityInfo {
		t.Errorf("expected an INFO finding for Info.plist without the key, got %+v", got)
	}

	infoWithKey := FileContext{RelPath: "Info.plist", Language: "plist", Lines: []string{"<key>ITSAppUsesNonExemptEncryption</key><false/>"}}
	if got := r.Check(infoWithKey); len(got) != 0 {
		t.Errorf("no finding expected when the key is present, got %+v", got)
	}

	expoNoKey := FileContext{RelPath: "app.json", Language: "json", Lines: []string{`{"expo":{"name":"X","ios":{"bundleIdentifier":"a.b"}}}`}}
	if got := r.Check(expoNoKey); len(got) == 0 {
		t.Error("expected a finding for an Expo app.json without usesNonExemptEncryption")
	}

	// app.config.js uses an unquoted `expo:` key — the rule must still fire (this
	// was dead code: the "expo" quoted gate never matched JS/TS configs).
	expoConfigJS := FileContext{RelPath: "app.config.js", Language: "javascript", Lines: []string{`export default { expo: { name: "X" } }`}}
	if !r.Applies(expoConfigJS) {
		t.Error("should apply to app.config.js")
	}
	if got := r.Check(expoConfigJS); len(got) == 0 {
		t.Error("expected a finding for app.config.js without usesNonExemptEncryption")
	}

	expoWithKey := FileContext{RelPath: "app.json", Language: "json", Lines: []string{`{"expo":{"ios":{"config":{"usesNonExemptEncryption":false}}}}`}}
	if got := r.Check(expoWithKey); len(got) != 0 {
		t.Errorf("no finding expected when usesNonExemptEncryption is set, got %+v", got)
	}

	// A non-Expo json (e.g. some other app.json) must not trip it.
	nonExpo := FileContext{RelPath: "app.json", Language: "json", Lines: []string{`{"name":"not-expo"}`}}
	if got := r.Check(nonExpo); len(got) != 0 {
		t.Errorf("no finding expected for non-Expo json, got %+v", got)
	}
}

// The §2.1 placeholder-content rule must not fire on SwiftUI's `placeholder:`
// parameter or example hint text. It used to match the bare word "placeholder",
// turning normal apps into dozens of warnings; re-adding it would fail this test.
func TestPlaceholderRuleIgnoresSwiftUIPlaceholder(t *testing.T) {
	r := ruleByID(t, "placeholder-content")

	clean := swiftCtx(
		`VaultTextField(label: "Email", text: $email, placeholder: "you@example.com")`,
		`SecureField(placeholder, text: $text)`,
		`VaultTextField(label: "CVC", text: $cvc, placeholder: "123")`,
	)
	if got := r.Check(clean); len(got) != 0 {
		t.Errorf("expected no findings for SwiftUI placeholders, got %d: %+v", len(got), got)
	}

	// Real placeholder content must still be caught.
	dirty := swiftCtx(`Text("Lorem ipsum dolor sit amet")`)
	if got := r.Check(dirty); len(got) == 0 {
		t.Errorf("expected a finding for real placeholder content")
	}
}

// §5.1.1 must recognize "Close account" / "cancel account" as deletion (Vault
// labels it "Close account") — but NOT "deactivate", which Apple deems
// insufficient.
func TestAccountDeleteAntiPatterns(t *testing.T) {
	r := ruleByID(t, "account-no-delete")
	suppress := []string{
		`Button("Close account") {}`,
		`func closeAccount() {}`,
		`onTap: deleteAccount`,
		`"Cancel account"`,
	}
	for _, line := range suppress {
		if !r.AntiPatternMatched(swiftCtx(line)) {
			t.Errorf("expected %q to count as account deletion", line)
		}
	}
	notSuppress := []string{
		`Button("Deactivate") {}`,      // deactivate != delete
		`let accountClosed = navPop()`, // incidental, not a deletion control
		`Button("Delete my data") {}`,  // GDPR data deletion != account deletion
		`let balance = 100`,
	}
	for _, line := range notSuppress {
		if r.AntiPatternMatched(swiftCtx(line)) {
			t.Errorf("expected %q NOT to count as account deletion", line)
		}
	}
}

// "Missing safeguard" rules describe one project-level fact — they must report
// once, not once per matching line.
func TestFirstMatchOnly(t *testing.T) {
	r := ruleByID(t, "account-no-delete")
	ctx := swiftCtx(
		`func createAccount() {}`,
		`struct SignUpScreen {}`,
		`button: createAccount`,
	)
	if got := r.Check(ctx); len(got) != 1 {
		t.Errorf("expected exactly 1 finding (firstMatchOnly), got %d", len(got))
	}
}
