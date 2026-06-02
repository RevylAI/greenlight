# greenlight

**Know before you submit.** Pre-submission compliance scanner for the Apple App Store.

Greenlight scans your app — source code, privacy manifests, IPA binaries, and App Store Connect metadata — against Apple's Review Guidelines, catching rejection risks before Apple does. Fully offline, no account, runs in under a second.

> **Optional runtime tier:** want to confirm flow-dependent guidelines (account deletion, restore purchases, Sign in with Apple) actually *work*, not just exist in source? `greenlight verify` validates them on a real device via [Revyl](https://revyl.com). It's entirely separate and opt-in — the static scanner above never needs it. See [`greenlight verify`](#greenlight-verify-path--runtime-flow-validation-via-revyl).

## Install

```bash
# Homebrew (macOS)
brew install revylai/tap/greenlight

# Go
go install github.com/RevylAI/greenlight/cmd/greenlight@latest

# Build from source
git clone https://github.com/RevylAI/greenlight.git
cd greenlight && make build
# Binary at: build/greenlight
```

## Quick Start

```bash
# Run EVERYTHING on your project — one command, zero uploads
greenlight preflight /path/to/your/project

# Include IPA for binary analysis
greenlight preflight . --ipa build.ipa
```

That's it. You get a full report in under a second.

## Commands

### `greenlight preflight [path]` — The one command to run

Runs all scanners in parallel. No account needed. Entirely offline.

```bash
greenlight preflight .                          # scan current directory
greenlight preflight ./my-app --ipa build.ipa   # with binary inspection
greenlight preflight . --format json            # JSON output for CI/CD
greenlight preflight . --output report.json     # write to file
```

**Scanners included:**

| Scanner | Checks |
|---------|--------|
| **metadata** | app.json / Info.plist: name, version, bundle ID format, icon, privacy policy URL, purpose strings |
| **codescan** | 30+ code patterns: private APIs, secrets, payment violations, missing ATT, social login, placeholders |
| **privacy** | PrivacyInfo.xcprivacy completeness, Required Reason APIs, tracking SDKs vs ATT implementation |
| **ipa** | Binary: Info.plist keys, launch storyboard, app icons, app size, framework privacy manifests |

### `greenlight codescan [path]` — Code pattern scan

```bash
greenlight codescan /path/to/project
```

Scans Swift, Objective-C, React Native, and Expo projects for:
- Private API usage (§2.5.1) — **CRITICAL**
- Hardcoded secrets/API keys (§1.6) — **CRITICAL**
- External payment for digital goods (§3.1.1) — **CRITICAL**
- Dynamic code execution (§2.5.2) — **CRITICAL**
- Cryptocurrency mining (§3.1.5) — **CRITICAL**
- Missing Sign in with Apple when using social login (§4.8)
- Missing Restore Purchases for IAP (§3.1.1)
- Missing ATT for ad/tracking SDKs (§5.1.2)
- Account creation without deletion option (§5.1.1)
- Placeholder content in strings (§2.1)
- References to competing platforms (§2.3)
- Hardcoded IPv4 addresses (§2.5)
- Insecure HTTP URLs (§1.6)
- Vague Info.plist purpose strings (§5.1.1)
- Expo config issues (§2.1)

### `greenlight privacy [path]` — Privacy manifest validator

```bash
greenlight privacy /path/to/project
```

Deep privacy compliance scan:
- PrivacyInfo.xcprivacy exists and is properly configured
- Required Reason APIs detected in code vs declared in manifest
- Tracking SDKs detected vs ATT implementation
- Cross-references everything automatically

### `greenlight ipa <path.ipa>` — Binary inspector

```bash
greenlight ipa /path/to/build.ipa
```

Inspects a built IPA for:
- PrivacyInfo.xcprivacy presence
- Info.plist completeness and purpose string quality
- App Transport Security configuration
- App icon presence and sizes
- Launch storyboard presence
- App size vs 200MB cellular download limit
- Embedded framework privacy manifests

### `greenlight scan --app-id <ID>` — App Store Connect checks

```bash
greenlight auth setup                    # one-time: configure API key
greenlight auth login                    # or: sign in with Apple ID
greenlight scan --app-id 6758967212     # run all tiers
```

API-based checks against your app in App Store Connect:
- Metadata completeness (descriptions, keywords, URLs)
- Screenshot verification for required device sizes
- Build processing status
- Age rating and encryption compliance
- Content analysis (platform references, placeholders)

### `greenlight verify [path]` — Runtime flow validation (via Revyl)

Static checks confirm a flow **exists** in your source. `verify` confirms it **works**
on a real device by handing flow-dependent guidelines to the [Revyl](https://revyl.com)
CLI and running the actual flow.

This catches what static analysis structurally cannot. A "Delete Account" button wired
to nothing **passes** codescan — the string `deleteAccount` is present, so §5.1.1 is
suppressed and you get GREENLIT — but it dead-ends at runtime, and Apple rejects it under
§5.1.1(v). `verify` runs the flow on a device and catches it.

```bash
greenlight verify .                       # dry-run-style: shows which flows are claimed
greenlight verify . --dry-run             # print the generated Revyl tests, no device
greenlight verify . --build-name "My App" \
  --var email=qa@acme.com --var password=secret   # run on a device
greenlight verify . --build-name "My App" --flows account-deletion --os-version "iOS 26.2"
```

Flows verified (only the ones your app actually claims are run):

| Flow | Guideline | What runtime proves that static can't |
|------|-----------|----------------------------------------|
| `account-deletion`   | §5.1.1 | The account is *actually deleted* — not that a `deleteAccount` string exists |
| `restore-purchases`  | §3.1.1 | "Restore Purchases" does something — not a silent no-op button |
| `sign-in-apple`      | §4.8   | The Apple sign-in sheet actually appears — not a dead control |

A failed flow becomes a `BLOCK` static analysis could never produce, with a shareable
Revyl report link as evidence.

> **Note:** Unlike every other greenlight command, `verify` is **not** offline. It needs
> the [`revyl` CLI](https://docs.revyl.com), a Revyl account (`revyl auth login`), and a
> registered build. It's a deliberately separate, opt-in tier — run `preflight` first to
> get GREENLIT, then `verify` before you submit.

### `greenlight guidelines` — Browse Apple's guidelines

```bash
greenlight guidelines list               # all sections
greenlight guidelines show 2.1           # specific guideline
greenlight guidelines search "privacy"   # full-text search
```

### Output formats

All scan commands support:

```bash
--format terminal   # colored terminal output (default)
--format json       # JSON for CI/CD pipelines
--output file.json  # write to file instead of stdout
```

## Claude Code Skill

Greenlight works as a Claude Code skill for AI-assisted compliance fixing. Claude runs the scan, reads the output, fixes every issue in your code, and re-runs until GREENLIT.

### Setup

Add the SKILL.md to your project's `.claude/` directory or install as a plugin:

```bash
# Copy skill file into your project
mkdir -p .claude/skills
cp /path/to/greenlight/SKILL.md .claude/skills/greenlight.md

# Or reference it in your CLAUDE.md
echo "See greenlight skill: /path/to/greenlight/SKILL.md" >> CLAUDE.md
```

Then tell Claude: *"Run greenlight preflight and fix everything until it passes"*

Claude will:
1. Run `greenlight preflight .`
2. Read every finding
3. Fix each issue (CRITICAL first, then WARN, then INFO)
4. Re-run and repeat until GREENLIT

## Codex Skill

Greenlight includes a Codex-native skill package at `codex-skill/`.

### Setup

```bash
mkdir -p ~/.codex/skills/app-store-preflight-compliance
cp -R codex-skill/* ~/.codex/skills/app-store-preflight-compliance/
```

Then in Codex, invoke:

```text
Use $app-store-preflight-compliance to run Greenlight preflight and fix all findings until GREENLIT.
```

## Architecture

```
greenlight
├── preflight         Run ALL checks — one command
│   ├── metadata      app.json / Info.plist local analysis
│   ├── codescan      30+ rejection-risk code patterns
│   ├── privacy       Privacy manifest + Required Reason APIs
│   └── ipa           Binary inspection (optional)
│
├── codescan          Code-only scanning
├── privacy           Privacy-only scanning
├── ipa               Binary-only inspection
│
├── verify            Runtime flow validation on a real device (via Revyl)
│   ├── account-deletion   §5.1.1 — the account is actually deleted
│   ├── restore-purchases  §3.1.1 — Restore Purchases isn't a no-op
│   └── sign-in-apple      §4.8   — the Apple sign-in sheet actually appears
│
├── scan              App Store Connect API checks (tiers 1-4)
│   ├── Tier 1        Metadata & completeness
│   ├── Tier 2        Content analysis
│   ├── Tier 3        Binary inspection
│   └── Tier 4        Historical pattern matching
│
├── auth              App Store Connect authentication
│   ├── login         Apple ID + 2FA session auth
│   ├── setup         API key configuration
│   ├── status        Show current auth state
│   └── logout        Remove credentials
│
└── guidelines        Built-in Apple Review Guidelines database
    ├── list          All 5 sections with subsections
    ├── show          Specific guideline details
    └── search        Full-text search
```

## CI/CD Integration

```yaml
# GitHub Actions
- name: App Store compliance check
  run: |
    greenlight preflight . --format json --output greenlight-report.json
    # Fail the pipeline if critical issues found
    if jq -e '.summary.critical > 0' greenlight-report.json > /dev/null; then
      echo "CRITICAL issues found — fix before submission"
      exit 1
    fi
```

```yaml
# JUnit output for test reporting (scan command only)
greenlight scan --app-id $APP_ID --format junit --output greenlight.xml
```

## Built by Revyl

Greenlight catches App Store rejections. [Revyl](https://revyl.com) catches bugs.

The mobile reliability platform. AI-powered testing for mobile apps — write tests in natural language, run them on real devices.
