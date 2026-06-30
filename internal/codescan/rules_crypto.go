package codescan

import "regexp"

// cryptoComplianceRules returns the Guideline 3.1.5(b) checks for apps that
// handle cryptocurrency.
//
// Unlike most code rules, these flag *process* obligations that static analysis
// cannot confirm, only detect the need for: an app that touches crypto must be
// published by an Organization account, and an app that facilitates exchange or
// transmission of crypto must be the licensed exchange itself (or an approved,
// law-compliant organization) in every region where it ships. Apple's review
// team routinely requests licensing evidence or a legal opinion for these apps,
// so surfacing the requirement before submission is the whole point.
//
// Both rules are firstMatchOnly (one finding per project — a crypto app is a
// project-level fact) and carry no antiPatterns, because the obligation cannot
// be discharged in source. A team that has handled it silences the reminder
// with an inline `// greenlight:ignore <rule-id>` directive.
func cryptoComplianceRules() []Rule {
	return []Rule{
		// WARN — a wallet/web3 integration is permitted, but only from an
		// Organization account. Individual-account crypto apps are rejected
		// under 3.1.5(b)(i), and this is invisible to a code scan.
		&PatternRule{
			id:        "crypto-wallet-org-account",
			title:     "Crypto wallet detected — Organization account required",
			guideline: "3.1.5",
			severity:  SeverityWarn,
			detail:    "Crypto wallet / web3 functionality detected. Guideline 3.1.5(b)(i): apps that facilitate virtual currency storage must be published by a developer enrolled as an Organization — Individual Apple Developer accounts are rejected. This is a process requirement a code scan cannot verify.",
			fix:       "Confirm the app ships under an Organization account. If it also lets users buy, sell, exchange, or transmit crypto (including fiat on/off-ramp), the heavier 3.1.5(b)(iii) requirements apply — see the crypto-exchange-licensing finding. Once confirmed, silence with `// greenlight:ignore crypto-wallet-org-account`.",
			languages: []string{"json", "typescript", "javascript", "swift", "objc"},
			patterns: []*regexp.Regexp{
				// Wallet / web3 SDKs as a quoted dependency key (package.json) or
				// import source (.ts/.js). The quotes bound the token so `web3`
				// can't match `web3modal`; an optional /subpath catches `viem/chains`.
				regexp.MustCompile(`(?i)['"](ethers|viem|wagmi|web3|@reown/appkit[\w-]*|@walletconnect/[\w-]+|@privy-io/[\w-]+|@web3auth/[\w-]+|@magic-sdk/[\w-]+|@dynamic-labs/[\w-]+|@solana/web3\.js|bitcoinjs-lib|@trustwallet/[\w-]+)(/[\w./-]+)?['"]`),
				// Native (Swift/ObjC) wallet libraries.
				regexp.MustCompile(`(?i)(import\s+web3swift|\bWalletCore\b|import\s+BigInt\s*//\s*web3)`),
			},
			firstMatchOnly: true,
		},
		// HIGH — facilitating exchange/transmission or fiat on/off-ramp is the
		// licensing-and-legal-opinion tier (3.1.5(b)(iii) + Guideline 5.0). This
		// is the single most common reason crypto apps stall in App Review.
		&PatternRule{
			id:        "crypto-exchange-licensing",
			title:     "Crypto exchange / on-ramp — licensing or legal opinion required",
			guideline: "3.1.5",
			severity:  SeverityHigh,
			detail:    "Crypto exchange, fiat on/off-ramp, or transmission functionality detected. Guideline 3.1.5(b)(iii): this is permitted only by the licensed exchange itself or an approved organization, in compliance with all applicable laws in every region the app is offered. App Review's crypto team routinely requests — via Resolution Center — money-transmission/VASP licensing evidence OR a legal opinion that licensing is not required, geo-restricted availability, and a working demo account. None of this can be verified by static analysis.",
			fix:       "Before submitting: (1) confirm an Organization Apple account; (2) prepare per-territory licensing documents or a counsel legal opinion mapped to 3.1.5(b)(iii) and Guideline 5.0; (3) geo-restrict App Store availability to authorized territories and gate sanctioned regions in-app; (4) provide a funded demo account and compliance notes in App Review notes. Once handled, silence with `// greenlight:ignore crypto-exchange-licensing`.",
			languages: []string{"json", "typescript", "javascript", "swift", "objc"},
			patterns: []*regexp.Regexp{
				// Fiat on/off-ramp and exchange-provider SDKs as a quoted token.
				// Every provider allows an optional scope/subpath so scoped SDK
				// packages match too (e.g. "@ramp-network/ramp-instant-sdk",
				// "@moonpay/react-native-moonpay-sdk", "transak-react-native-sdk").
				regexp.MustCompile(`(?i)['"]@?(moonpay|transak|ramp-network|onramper|banxa|mercuryo|sardine|wyre)[\w/.-]*['"]`),
				// Exchange / ramp / P2P domain phrases in user copy or identifiers.
				// Hyphen/underscore/camel only for "on/off ramp" so a freeway
				// "on ramp" sentence can't trip a HIGH finding.
				regexp.MustCompile(`(?i)\b(fiat[_-]?(on|off)[_-]?ramp|(on|off)[_-]?ramp(er|s)?\b|crypto[\s_-]?exchange|buy[\s_-]?crypto|sell[\s_-]?crypto|p2p[\s_-]?trad)`),
			},
			firstMatchOnly: true,
		},
	}
}
