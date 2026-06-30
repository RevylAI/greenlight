package codescan

import "testing"

func jsonCtx(lines ...string) FileContext {
	return FileContext{Path: "package.json", RelPath: "package.json", Lines: lines, Language: "json"}
}

// A wallet/web3 SDK in dependencies or imports triggers the 3.1.5(b)(i)
// Organization-account reminder; unrelated dependencies do not.
func TestCryptoWalletOrgAccount(t *testing.T) {
	r := ruleByID(t, "crypto-wallet-org-account")

	fire := []FileContext{
		jsonCtx(`    "ethers": "^6.13.0",`),
		jsonCtx(`    "@privy-io/expo": "0.0.0",`),
		jsonCtx(`    "@reown/appkit-wagmi-react-native": "1.0.0",`),
		tsCtx(`import { createWalletClient } from "viem";`),
		tsCtx(`import { Connection } from "@solana/web3.js";`),
		tsCtx(`import { useAccount } from 'wagmi/actions';`),
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
		tsCtx(`const etherealMessage = "hello";`), // "ethers" must be the whole quoted token
	}
	for i, ctx := range noFire {
		if got := r.Check(ctx); len(got) != 0 {
			t.Errorf("no-fire case %d: expected no finding for %q, got %+v", i, ctx.Lines[0], got)
		}
	}

	if got := r.Check(jsonCtx(`    "ethers": "^6.13.0",`)); len(got) > 0 && got[0].Severity != SeverityWarn {
		t.Errorf("crypto-wallet-org-account should be WARN, got %s", got[0].Severity)
	}
}

// Exchange / fiat on-off-ramp / P2P signals trigger the 3.1.5(b)(iii)
// licensing/legal-opinion HIGH advisory.
func TestCryptoExchangeLicensing(t *testing.T) {
	r := ruleByID(t, "crypto-exchange-licensing")

	fire := []FileContext{
		jsonCtx(`    "@moonpay/react-native-moonpay-sdk": "1.0.0",`),
		jsonCtx(`    "transak-react-native-sdk": "1.0.0",`),
		tsCtx(`export const FIAT_ON_RAMP_URL = "https://onramp.example";`),
		tsCtx(`const title = "Crypto exchange";`),
		tsCtx(`function buyCrypto() {}`),
		tsCtx(`const tab = "p2p-trading";`),
	}
	for i, ctx := range fire {
		got := r.Check(ctx)
		if len(got) == 0 {
			t.Errorf("fire case %d: expected a finding for %q", i, ctx.Lines[0])
			continue
		}
		if got[0].Severity != SeverityHigh {
			t.Errorf("fire case %d: crypto-exchange-licensing should be HIGH, got %s", i, got[0].Severity)
		}
	}

	noFire := []FileContext{
		tsCtx(`// take the highway on ramp to the bridge`), // comment line, and spaced "on ramp"
		tsCtx(`const note = "merge onto the on ramp";`),    // spaced "on ramp" is not on-ramp/onramp
		jsonCtx(`    "react-query": "5.0.0",`),
	}
	for i, ctx := range noFire {
		if got := r.Check(ctx); len(got) != 0 {
			t.Errorf("no-fire case %d: expected no finding for %q, got %+v", i, ctx.Lines[0], got)
		}
	}
}

// Both crypto advisories are project-level facts: one finding per project even
// when many files match.
func TestCryptoRulesCollapseToOnePerProject(t *testing.T) {
	for _, id := range []string{"crypto-wallet-org-account", "crypto-exchange-licensing"} {
		r := ruleByID(t, id)
		if !r.firstMatchOnly {
			t.Errorf("%s should be firstMatchOnly so it reports once per project", id)
		}
		// No antiPatterns: the obligation can't be discharged in source.
		if len(r.antiPatterns) != 0 {
			t.Errorf("%s should have no antiPatterns (cannot be fixed in code)", id)
		}
	}
}

// An inline ignore directive lets a team that has handled the obligation
// silence the advisory.
func TestCryptoAdvisoryRespectsIgnoreDirective(t *testing.T) {
	r := ruleByID(t, "crypto-exchange-licensing")
	ctx := tsCtx(`const title = "Crypto exchange"; // greenlight:ignore crypto-exchange-licensing`)
	if got := r.Check(ctx); len(got) != 0 {
		t.Errorf("expected the ignore directive to suppress the advisory, got %+v", got)
	}
}
