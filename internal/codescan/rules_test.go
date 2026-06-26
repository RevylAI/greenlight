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
