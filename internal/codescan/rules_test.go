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
