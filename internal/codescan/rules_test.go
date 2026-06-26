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
		`let s = "UIWebView"`,                            // string literal, not usage
		`logEvent("UIWebView_fallback_shown")`,           // identifier inside a string
		`let w = WKWebView() // migrated from UIWebView`, // trailing-comment mention
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
