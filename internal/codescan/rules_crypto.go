package codescan

import "regexp"

// cryptoComplianceRules returns the Guideline 3.1.5(b) checks for apps that
// handle cryptocurrency.
//
// These flag *process* obligations a code scan can detect the need for but not
// verify: a crypto wallet app must be offered by a developer enrolled as an
// organization, and an app that facilitates exchange or transmission of crypto
// must be offered by the exchange itself. App Review commonly follows up (in the
// Resolution Center) asking for licensing evidence or a legal opinion, so
// surfacing the requirement before submission is the point.
//
// Calibration matters because HIGH findings fail `preflight --exit-code`:
//   - crypto-exchange-sdk is HIGH, but only fires on a real provider-SDK package
//     identifier (scoped or -suffixed), so a bare word like "sardine" in a
//     non-crypto app can't trip CI.
//   - crypto-wallet-org-account and crypto-exchange-signals are WARN — weaker
//     wallet-SDK and copy/phrase heuristics that inform without gating.
//
// All three are firstMatchOnly (a crypto app is a project-level fact) and carry
// no antiPatterns, since the obligation can't be discharged in source. Silence a
// finding on a code line with `// greenlight:ignore <rule-id>`, or — because the
// SDK rules fire on package.json, where a comment can't live — disable/downgrade
// it in .greenlight.yml (`rules: { <rule-id>: { enabled: false } }`).
func cryptoComplianceRules() []Rule {
	return []Rule{
		// WARN — a wallet/web3 integration is permitted, but only from an
		// Organization account (3.1.5(b), Wallets). WARN, not HIGH: the mitigation
		// (organization enrollment) lives outside the code, so this informs rather
		// than gates CI.
		&PatternRule{
			id:        "crypto-wallet-org-account",
			title:     "Crypto wallet detected — Organization account required",
			guideline: "3.1.5",
			severity:  SeverityWarn,
			detail:    "Crypto wallet / web3 functionality detected. Guideline 3.1.5(b) allows apps to facilitate virtual currency storage only when they are offered by a developer enrolled as an Organization — Individual Apple Developer accounts are rejected. A code scan can't verify which account type ships the app.",
			fix:       "Confirm the app ships under an Organization account. If it also lets users buy, sell, exchange, or transmit crypto (including fiat on/off-ramp), see crypto-exchange-sdk / crypto-exchange-signals. Silence with `// greenlight:ignore crypto-wallet-org-account`, or in .greenlight.yml (`rules: { crypto-wallet-org-account: { enabled: false } }`).",
			languages: []string{"json", "typescript", "javascript", "swift", "objc"},
			patterns: []*regexp.Regexp{
				// Wallet / web3 SDKs as a quoted dependency key (package.json) or
				// import specifier (.ts/.js). Scoped names are listed with their
				// scope so `@wagmi/core` / `@ethersproject/*` aren't slipped past
				// the bare-name alternatives; an optional /subpath catches
				// `viem/chains`. The quotes bound the token so `web3` can't match
				// `web3modal`.
				regexp.MustCompile(`(?i)['"](ethers|@ethersproject/[\w-]+|viem|wagmi|@wagmi/[\w-]+|web3|@reown/appkit[\w-]*|@walletconnect/[\w-]+|@privy-io/[\w-]+|@web3auth/[\w-]+|@magic-sdk/[\w-]+|@dynamic-labs/[\w-]+|@solana/web3\.js|@coinbase/wallet-sdk|@rainbow-me/[\w-]+|thirdweb|@web3-onboard/[\w-]+|bitcoinjs-lib|@trustwallet/[\w-]+)(/[\w./-]+)?['"]`),
				// Native (Swift/ObjC) wallet libraries, anchored to an import so a
				// bare `WalletCore` identifier (Apple Wallet / loyalty code) or a
				// mention in prose doesn't fire.
				regexp.MustCompile(`(?i)(import\s+web3swift\b|import\s+WalletCore\b|#import\s*<WalletCore)`),
			},
			firstMatchOnly: true,
		},
		// HIGH — a fiat on/off-ramp or exchange provider SDK is a strong, low-noise
		// signal that the app facilitates exchange/transmission, the tier App
		// Review scrutinizes most (3.1.5(b), Exchanges). Matched only as a real
		// package identifier so it won't false-positive on non-crypto copy.
		&PatternRule{
			id:        "crypto-exchange-sdk",
			title:     "Crypto exchange / on-ramp SDK — licensing or legal opinion likely required",
			guideline: "3.1.5",
			severity:  SeverityHigh,
			detail:    "A fiat on/off-ramp or crypto exchange provider SDK is a dependency (MoonPay, Transak, Ramp, Banxa, Mercuryo, Sardine, ...). Guideline 3.1.5(b) permits facilitating transactions or transmissions of cryptocurrency on an approved exchange only when they are offered by the exchange itself. In practice App Review's crypto team asks — via the Resolution Center — for evidence the operator is licensed (or a legal opinion that it isn't required in the shipped regions), region-restricted availability, and a working demo account. A code scan can see the SDK but verify none of this.",
			fix:       "Before submitting: (1) ship under an Organization Apple account; (2) prepare per-territory licensing documents or a counsel legal opinion, plus Guideline 5.0 compliance; (3) restrict App Store availability to authorized regions and gate sanctioned ones in-app; (4) add a funded demo account and notes for the reviewer. This fires on a package.json dependency, so once handled silence it in .greenlight.yml (`rules: { crypto-exchange-sdk: { enabled: false } }`) — a comment directive can't live in JSON.",
			languages: []string{"json", "typescript", "javascript", "swift", "objc"},
			patterns: []*regexp.Regexp{
				// Provider SDKs matched only as a package identifier: a scope
				// subpath (@moonpay/react-native-moonpay-sdk, @ramp-network/...) or a
				// -suffixed package (transak-react-native-sdk, moonpay-sdk). The
				// required /subpath-or-suffix means bare tokens ("sardine",
				// "sardines", "wyred", "moonpayments", "banxample") cannot match.
				regexp.MustCompile(`(?i)['"]@?(moonpay|transak|ramp-network|onramper|banxa|mercuryo|sardine(?:-ai)?|sendwyre|wyre)(/[\w.-]+|-[\w.-]*(sdk|react-native|widget|instant|onramp|checkout|api)[\w.-]*)['"]`),
			},
			firstMatchOnly: true,
		},
		// WARN — loose exchange/on-ramp/P2P phrases in copy or identifiers. Weak
		// signals (a "Buy Crypto" button, a disclaimer), so WARN, negation-aware,
		// and requiring a real separator on the ramp phrase to avoid road/ride
		// "onramp" copy. A real provider SDK trips the HIGH rule above.
		&PatternRule{
			id:        "crypto-exchange-signals",
			title:     "Crypto exchange / on-ramp signals in copy",
			guideline: "3.1.5",
			severity:  SeverityWarn,
			detail:    "Exchange / on-ramp / P2P wording found in app copy or identifiers (e.g. \"crypto exchange\", \"buy crypto\", \"on-ramp\"). If the app itself facilitates exchange, transmission, or fiat on/off-ramp of cryptocurrency, Guideline 3.1.5(b) applies and App Review commonly asks for licensing evidence or a legal opinion, region-restricted availability, and a demo account. If the app only links out to a third-party exchange and doesn't perform the transaction, this is informational.",
			fix:       "Confirm whether the app performs — rather than merely links to — crypto exchange/transmission. If it does, prepare the 3.1.5(b) materials before submitting. Silence with `// greenlight:ignore crypto-exchange-signals`, or in .greenlight.yml (`rules: { crypto-exchange-signals: { enabled: false } }`).",
			languages: []string{"json", "typescript", "javascript", "swift", "objc"},
			patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)\b(crypto[\s_-]?currency[\s_-]?exchange|crypto[\s_-]?exchange|(buy|sell|trade|swap)[\s_-]?crypto|(buy|sell)[\s_-]?(bitcoin|btc|ethereum|usdt|usdc)|fiat[\s_-]?(on|off)[\s_-]?ramps?|(on|off)[_-]ramps?\b|p2p[\s_-]?trad)`),
			},
			ignorePatterns: []*regexp.Regexp{
				// Skip obvious negations/disclaimers ("this app is not a crypto
				// exchange", "does not buy crypto") so a denial doesn't read as a
				// claim. Whole-line skip; a real crypto app trips other lines.
				regexp.MustCompile(`(?i)\b(not|never|no|without|isn['’]?t|aren['’]?t|does[n']?['’]?t|do[n']?['’]?t|won['’]?t|can[n']?o?['’]?t)\b.{0,30}?(crypto|exchange|on[_-]?ramp|off[_-]?ramp|bitcoin)`),
			},
			firstMatchOnly: true,
		},
	}
}
