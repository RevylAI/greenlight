package codescan

import (
	"strings"
	"testing"
)

func jsonCtx(lines ...string) FileContext {
	return FileContext{Path: "package.json", RelPath: "package.json", Lines: lines, Language: "json"}
}

func objcCtx(lines ...string) FileContext {
	return FileContext{Path: "X.mm", RelPath: "X.mm", Lines: lines, Language: "objc"}
}

// A wallet/web3 SDK in dependencies or imports triggers the WARN
// Organization-account reminder; unrelated deps and bare identifiers do not.
func TestCryptoWalletOrgAccount(t *testing.T) {
	r := ruleByID(t, "crypto-wallet-org-account")
	if r.severity != SeverityWarn {
		t.Fatalf("crypto-wallet-org-account should be WARN, got %s", r.severity)
	}

	fire := []FileContext{
		jsonCtx(`    "ethers": "^6.13.0",`),
		jsonCtx(`    "@privy-io/expo": "0.0.0",`),
		jsonCtx(`    "@reown/appkit-wagmi-react-native": "1.0.0",`),
		jsonCtx(`    "@wagmi/core": "2.0.0",`),           // scoped form (reviewer coverage gap)
		jsonCtx(`    "@ethersproject/contracts": "5.0"`), // scoped ethers
		jsonCtx(`    "@coinbase/wallet-sdk": "4.0.0",`),
		jsonCtx(`    "@rainbow-me/rainbowkit": "2.0.0",`),
		jsonCtx(`    "thirdweb": "5.0.0",`),
		jsonCtx(`    "@web3-onboard/core": "2.0.0",`),
		tsCtx(`import { createWalletClient } from "viem";`),
		tsCtx(`import { Connection } from "@solana/web3.js";`),
		tsCtx(`import { useAccount } from 'wagmi/actions';`),
		swiftCtx(`import WalletCore`),
		objcCtx(`#import <WalletCore/WalletCore.h>`),
	}
	for i, ctx := range fire {
		if got := r.Check(ctx); len(got) == 0 {
			t.Errorf("fire case %d: expected a finding for %q", i, ctx.Lines[0])
		}
	}

	noFire := []FileContext{
		jsonCtx(`    "web3modal-legacy-unrelated": "1.0.0",`), // quotes bound the token: web3 != web3modal...
		jsonCtx(`    "react-native": "0.83.6",`),
		tsCtx(`import axios from "axios";`),
		tsCtx(`const etherealMessage = "hello";`),              // "ethers" must be the whole quoted token
		swiftCtx(`let pass = WalletCore.makeApplePass()`),      // bare WalletCore identifier (Apple Wallet) — needs `import`
		swiftCtx(`// see WalletCore for the Trust Wallet lib`), // prose mention
	}
	for i, ctx := range noFire {
		if got := r.Check(ctx); len(got) != 0 {
			t.Errorf("no-fire case %d: expected no finding for %q, got %+v", i, ctx.Lines[0], got)
		}
	}
}

// The HIGH exchange-SDK rule fires only on real provider package identifiers
// (scoped or -suffixed), never on bare words — so it can't fail a non-crypto
// app's `preflight --exit-code`.
func TestCryptoExchangeSDK(t *testing.T) {
	r := ruleByID(t, "crypto-exchange-sdk")
	if r.severity != SeverityHigh {
		t.Fatalf("crypto-exchange-sdk should be HIGH, got %s", r.severity)
	}

	fire := []FileContext{
		jsonCtx(`    "@moonpay/react-native-moonpay-sdk": "1.0.0",`),
		jsonCtx(`    "transak-react-native-sdk": "1.0.0",`),
		jsonCtx(`    "@ramp-network/ramp-instant-sdk": "4.0.0",`), // scoped pkg with /subpath
		jsonCtx(`    "@sardine-ai/react-native-sardine": "1.0.0",`),
		jsonCtx(`    "@transak/transak-sdk": "3.0.0",`),
	}
	for i, ctx := range fire {
		got := r.Check(ctx)
		if len(got) == 0 {
			t.Errorf("fire case %d: expected a HIGH finding for %q", i, ctx.Lines[0])
			continue
		}
		if got[0].Severity != SeverityHigh {
			t.Errorf("fire case %d: want HIGH, got %s", i, got[0].Severity)
		}
	}

	// Reviewer's blocking false positives: bare words that merely start with a
	// provider name must NOT trip the HIGH rule.
	noFire := []FileContext{
		jsonCtx(`  "ingredients": ["sardine", "sardines", "tuna"],`),
		tsCtx(`const fish = "sardine";`),
		tsCtx(`const a = "wyred"; const b = "moonpayments"; const c = "banxample";`),
		jsonCtx(`    "moonshot-ui": "1.0.0",`),
		tsCtx(`const note = "This app is not a crypto exchange and does not buy crypto";`),
		jsonCtx(`    "react-query": "5.0.0",`),
	}
	for i, ctx := range noFire {
		if got := r.Check(ctx); len(got) != 0 {
			t.Errorf("no-fire case %d: expected NO HIGH finding for %q, got %+v", i, ctx.Lines[0], got)
		}
	}
}

// The WARN signals rule catches loose exchange/on-ramp phrases, skips obvious
// negations, and requires a real separator on the ramp phrase.
func TestCryptoExchangeSignals(t *testing.T) {
	r := ruleByID(t, "crypto-exchange-signals")
	if r.severity != SeverityWarn {
		t.Fatalf("crypto-exchange-signals should be WARN (must not fail --exit-code), got %s", r.severity)
	}

	fire := []FileContext{
		tsCtx(`const title = "Crypto exchange";`),
		tsCtx(`const t = "cryptocurrency exchange";`),
		tsCtx(`function buyCrypto() {}`),
		tsCtx(`const cta = "Trade crypto";`),
		tsCtx(`const u = "fiat on-ramp";`),
		tsCtx(`const tab = "p2p-trading";`),
		tsCtx(`const link = "take the on-ramp to Coinbase";`), // separator present
	}
	for i, ctx := range fire {
		got := r.Check(ctx)
		if len(got) == 0 {
			t.Errorf("fire case %d: expected a WARN finding for %q", i, ctx.Lines[0])
			continue
		}
		if got[0].Severity != SeverityWarn {
			t.Errorf("fire case %d: want WARN, got %s", i, got[0].Severity)
		}
	}

	// Non-comment lines that exercise the regex and must NOT fire.
	noFire := []FileContext{
		tsCtx(`const s = "take the next onramp";`),                           // bare onramp, no separator (ride-share)
		tsCtx(`const s = "merge onto the highway offramp soon";`),            // bare offramp
		tsCtx(`const d = "This app is not a crypto exchange";`),              // negation
		tsCtx(`const d = "we do not buy crypto or bitcoin on your behalf";`), // negation
		tsCtx(`const x = "sardines and tuna";`),
	}
	for i, ctx := range noFire {
		if got := r.Check(ctx); len(got) != 0 {
			t.Errorf("no-fire case %d: expected no finding for %q, got %+v", i, ctx.Lines[0], got)
		}
	}
}

// A known exchange/wallet brand as a domain or SDK package fires the WARN brand
// rule; the same brand words in unrelated code (Google Gemini, "stargate.io",
// the mythical kraken, a bare "coinbase" string) do not.
func TestCryptoExchangeBrand(t *testing.T) {
	r := ruleByID(t, "crypto-exchange-brand")
	if r.severity != SeverityWarn {
		t.Fatalf("crypto-exchange-brand should be WARN, got %s", r.severity)
	}

	fire := []FileContext{
		tsCtx(`const APPLINK = "applinks:unigox.com";`),   // the app's own brand
		jsonCtx(`    "@unigox/web-app-shared": "1.0.0",`), // scoped brand package
		tsCtx(`const api = "https://api.coinbase.com/v2/prices";`),
		tsCtx(`const url = "https://www.binance.com/en";`),
		tsCtx(`const ex = "https://crypto.com/exchange";`),
		jsonCtx(`    "ccxt": "4.4.0",`), // multi-exchange trading lib
		jsonCtx(`    "@kucoin/api": "1.0.0",`),
	}
	for i, ctx := range fire {
		if got := r.Check(ctx); len(got) == 0 {
			t.Errorf("fire case %d: expected a finding for %q", i, ctx.Lines[0])
		}
	}

	noFire := []FileContext{
		tsCtx(`const ai = "https://gemini.google.com/app";`), // Google Gemini, not the exchange
		tsCtx(`const repo = "https://stargate.io/docs";`),    // \bgate anchored, "stargate" excluded
		tsCtx(`const h = crypto.createHash("sha256");`),      // node crypto module, no .com
		tsCtx(`const brand = "coinbase";`),                   // bare word, no domain/SDK anchor
		swiftCtx(`let monster = Kraken(tentacles: 8)`),       // mythical creature identifier
		jsonCtx(`    "gatekeeper": "1.0.0",`),
	}
	for i, ctx := range noFire {
		if got := r.Check(ctx); len(got) != 0 {
			t.Errorf("no-fire case %d: expected no finding for %q, got %+v", i, ctx.Lines[0], got)
		}
	}
}

// All crypto advisories are project-level facts: firstMatchOnly, no
// antiPatterns.
func TestCryptoRulesShape(t *testing.T) {
	for _, id := range []string{"crypto-wallet-org-account", "crypto-exchange-sdk", "crypto-exchange-signals", "crypto-exchange-brand"} {
		r := ruleByID(t, id)
		if !r.firstMatchOnly {
			t.Errorf("%s should be firstMatchOnly so it reports once per project", id)
		}
		if len(r.antiPatterns) != 0 {
			t.Errorf("%s should have no antiPatterns (cannot be fixed in code)", id)
		}
		// Only crypto-exchange-sdk is allowed to be HIGH (it gates CI); the others
		// must stay WARN so non-crypto false positives never fail --exit-code.
		if id != "crypto-exchange-sdk" && r.severity == SeverityHigh {
			t.Errorf("%s must not be HIGH", id)
		}
	}
}

// Fix text must recommend the supported space-form directive and, since these
// fire on package.json, the .greenlight.yml suppression path — never the
// bracketed form the scanner does not honor.
func TestCryptoFixTextSuppressionSyntax(t *testing.T) {
	for _, id := range []string{"crypto-wallet-org-account", "crypto-exchange-sdk", "crypto-exchange-signals", "crypto-exchange-brand"} {
		fix := ruleByID(t, id).fix
		if strings.Contains(fix, "greenlight:ignore["+id+"]") {
			t.Errorf("%s fix uses the bracketed directive form, which the scanner does not honor", id)
		}
		if !strings.Contains(fix, ".greenlight.yml") {
			t.Errorf("%s fix should point to .greenlight.yml (package.json hits can't carry an inline directive)", id)
		}
	}
}

// An inline ignore directive silences a code-line hit for the WARN phrase rule.
func TestCryptoSignalsRespectsIgnoreDirective(t *testing.T) {
	r := ruleByID(t, "crypto-exchange-signals")
	ctx := tsCtx(`const title = "Crypto exchange"; // greenlight:ignore crypto-exchange-signals`)
	if got := r.Check(ctx); len(got) != 0 {
		t.Errorf("expected the ignore directive to suppress the advisory, got %+v", got)
	}
}
