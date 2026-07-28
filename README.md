# greenlight

[![Release](https://img.shields.io/github/v/release/RevylAI/greenlight?color=2ea44f)](https://github.com/RevylAI/greenlight/releases)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.24+-00ADD8?logo=go&logoColor=white)](go.mod)
[![Powered by Revyl](https://img.shields.io/badge/powered%20by-Revyl-1C1833)](https://revyl.com?utm_source=greenlight&utm_medium=readme&utm_campaign=badge)

**Know before you submit.** Pre-submission compliance scanner for the Apple App Store and Google Play.

Greenlight reads your app (source code, privacy manifests, Android manifests and Gradle builds, IPA binaries, App Store Connect metadata) and checks it against Apple's Review Guidelines and Google Play's Developer Program Policies. Every finding cites the rule it comes from. No account, no uploads, no network. A full preflight on a mid-size project finishes in single-digit milliseconds.

A static scan can only prove a flow *exists*. `greenlight verify` proves it *works*: it runs your account-deletion, restore-purchases, and Sign in with Apple flows on a cloud device and fails the build if any of them dead-ends. That tier is powered by [Revyl](https://revyl.com?utm_source=greenlight&utm_medium=readme&utm_campaign=intro) and needs a free account. Everything else on this page runs offline. See [`greenlight verify`](#greenlight-verify-path).

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

## Quick start

```bash
# Everything, one command, zero uploads
greenlight preflight /path/to/your/project

# Include an IPA for binary analysis
greenlight preflight . --ipa build.ipa

# Gate CI on it
greenlight preflight . --exit-code
```

## Severity

Four levels. The top two fail a CI gate; the bottom two are advisory.

| Level | Meaning |
|-------|---------|
| CRITICAL | Rejection or install failure is near-certain. Fix before you submit. |
| HIGH | A published deadline, a required declaration, or a check that fails at runtime. |
| WARN | Likely to draw reviewer attention or an information request. |
| INFO | Best practice. |

`--exit-code` trips on CRITICAL and HIGH, and on a scanner that crashed, so an incomplete scan never reports as a pass.

## Commands

### `greenlight preflight [path]`

Runs every applicable scanner in parallel. Android and iOS projects in one repo are both picked up, so a cross-platform app is checked against both stores in a single pass.

```bash
greenlight preflight .                          # scan current directory
greenlight preflight ./my-app --ipa build.ipa   # with binary inspection
greenlight preflight . --format json            # JSON for CI
greenlight preflight . --format sarif --output greenlight.sarif
greenlight preflight . --exit-code              # non-zero on CRITICAL/HIGH
```

| Scanner | Checks |
|---------|--------|
| metadata | app.json / Info.plist: name, version, bundle ID format, icon, privacy policy URL, purpose strings |
| codescan | 24 rules over Swift, Objective-C, React Native, and Expo source |
| privacy | PrivacyInfo.xcprivacy completeness, Required Reason APIs, tracking SDKs vs ATT |
| playscan | Google Play policy, target API deadline, restricted permissions, foreground service types, Play Billing version (Android projects only) |
| ipa | Binary: Info.plist keys, launch storyboard, icons, app size, framework privacy manifests |

Adding `--verify` extends the same command into the runtime tier, so one invocation covers static and runtime:

```bash
greenlight preflight . --verify --build-name "My App" \
  --var email=qa@acme.com --var password=secret --exit-code
```

`--verify` accepts the same targeting flags as the standalone command: `--artifact`, `--build-name`, `--device-model`, `--os-version`, `--var`.

### `greenlight codescan [path]`

```bash
greenlight codescan /path/to/project
greenlight codescan . --config path/to/.greenlight.yml
```

24 rules, roughly 60 patterns, over Swift, Objective-C, React Native, and Expo.

CRITICAL:

- Private API usage (§2.5.1)
- Hardcoded secrets and API keys (§1.6)
- External payment for digital goods (§3.1.1)
- Dynamic code execution (§2.5.2)
- Cryptocurrency mining (§3.1.5)
- UIWebView, a removed API and a hard rejection (§2.5.1)

HIGH:

- Missing Sign in with Apple alongside social login (§4.8)
- Missing Restore Purchases with IAP (§3.1.1)
- Missing ATT with ad or tracking SDKs (§5.1.2)
- Account creation with no deletion path (§5.1.1)
- A crypto exchange or on-ramp SDK, which usually needs licensing or a legal opinion (§3.1.5(b))

WARN:

- Crypto wallet, which requires an Organization account (§3.1.5(b)), plus exchange signals in copy and references to exchange brands
- Insecure HTTP URLs (§1.6)
- Vague Info.plist purpose strings, and missing required privacy keys (§5.1.1)
- Placeholder content left in strings (§2.1)
- References to competing platforms (§2.3)
- Hardcoded IPv4 addresses (§2.5)
- WebView-only app pattern (§4.2)
- Expo config problems (§2.1)

INFO: debug logging left in production code (§2.1), and no encryption export-compliance declaration.

Rules that describe a project-level fact, such as "no account deletion anywhere", report once for the whole project rather than once per file that triggers them.

### `greenlight playscan [path]`

```bash
greenlight playscan /path/to/project
greenlight playscan --apk app-release.apk   # built artifact: merged manifest
greenlight playscan --aab app-release.aab   # app bundle
greenlight playscan . --format json
greenlight playscan . --exit-code
```

Checks an Android app against Google Play's Developer Program Policies and its published distribution deadlines. Every finding links the policy page it comes from.

Deadlines:

- Target API level. New apps and updates must target API 36 from August 31, 2026. Apps below API 35 already lose distribution to new users on newer devices. CRITICAL / HIGH
- Play Billing Library. v7 and below lose support on August 31, 2026, and there is no direct v7 to v9 upgrade path. Versions reached through a variable or a version catalog `version.ref` are resolved. HIGH

Restricted permissions, each of which needs an approved use case or a declaration form:

- SMS and Call Log, including the July 2026 change that drops phone-call account verification as a permitted `READ_CALL_LOG` use
- `MANAGE_EXTERNAL_STORAGE` (All files access)
- `QUERY_ALL_PACKAGES`, `REQUEST_INSTALL_PACKAGES`
- `ACCESS_BACKGROUND_LOCATION`, which needs a declaration and a demo video
- Broad photo and video access over the system Photo Picker (API 33+)
- Accessibility Service, VPN service, and device admin, which are declared as a component's `android:permission` rather than a `<uses-permission>`
- Overlays, usage stats
- Contacts, ahead of the 2026 Contact Permissions policy

Manifest and build:

- Foreground services missing the base `FOREGROUND_SERVICE` permission, or a declared type missing its `FOREGROUND_SERVICE_*` permission. Both throw at `startForeground()`. CRITICAL
- `specialUse` foreground services, which need a Console justification
- `android:exported` missing on components with an intent filter (API 31+), which makes the package fail to install. CRITICAL
- `android:debuggable="true"`. CRITICAL
- `android:usesCleartextTraffic="true"`
- An ads SDK shipped without `com.google.android.gms.permission.AD_ID`, which silently returns a zeroed advertising ID
- Account creation without the required in-app *and* web deletion paths

`--apk` and `--aab` read the *merged* manifest, so they see permissions contributed by library manifests that a source scan structurally cannot. Every check above runs against a built artifact, plus native code:

- 16 KB page size. Google Play requires apps targeting Android 15+ to support 16 KB memory pages. Greenlight checks ELF `LOAD` segment alignment on `arm64-v8a` libraries, 16 KB zip alignment of uncompressed libraries, and `GNU_RELRO` presence. CRITICAL / HIGH

Both formats are decoded in pure Go, an APK's compiled binary XML and an AAB's protobuf manifest alike, so no Android SDK, `aapt2`, or `bundletool` is required.

On scope: a source scan reads the `AndroidManifest.xml` and Gradle files in your repo, which is the pre-merge manifest. Permissions contributed by library manifests only appear once the build merges them, so a clean source scan is not proof of a clean merged manifest. Scan the built artifact to close that gap. `targetSdk` is resolved from the app module, convention plugins (`build-logic/`, `buildSrc/`, `build-plugin/`), version catalogs, `gradle.properties`, and named constants; when it cannot be resolved, the scan says so instead of reporting a pass.

### `greenlight privacy [path]`

```bash
greenlight privacy /path/to/project
```

Checks that PrivacyInfo.xcprivacy exists and is filled in, finds Required Reason APIs used in code and compares them against what the manifest declares, and cross-references detected tracking SDKs against your ATT implementation.

### `greenlight ipa <path.ipa>`

```bash
greenlight ipa /path/to/build.ipa
```

Plists are parsed for real, binary and XML both, rather than string-matched. Inspects:

- PrivacyInfo.xcprivacy presence
- Info.plist completeness and purpose string quality
- App Transport Security configuration
- App icon presence and sizes, including icons that live in Assets.car
- Launch storyboard presence
- App size against the 200 MB cellular download limit
- Embedded framework privacy manifests

### `greenlight scan --app-id <ID>`

```bash
greenlight auth setup                    # one-time: configure API key
greenlight auth login                    # or: sign in with Apple ID
greenlight scan --app-id 6758967212      # run all tiers
```

API-based checks against your app in App Store Connect: metadata completeness, screenshots for required device sizes, build processing status, age rating and encryption compliance, and content analysis for platform references and placeholders.

### `greenlight verify [path]`

Static checks confirm a flow *exists* in your source. `verify` confirms it *works*, by handing flow-dependent guidelines to the [Revyl](https://revyl.com?utm_source=greenlight&utm_medium=readme&utm_campaign=verify) CLI and running them on a cloud device.

This is the gap static analysis cannot close. A "Delete Account" button wired to nothing passes codescan: the string `deleteAccount` is in the source, §5.1.1 is suppressed, and you get GREENLIT. At runtime it dead-ends, and Apple rejects under §5.1.1(v). `verify` taps the button.

```bash
greenlight verify . --dry-run                     # show claimed flows + generated tests, no device
greenlight verify . --build-name "My App" \
  --var email=qa@acme.com --var password=secret
greenlight verify . --build-name "My App" --flows account-deletion --os-version "iOS 26.2"
greenlight verify . --artifact build/MyApp.app --build-name "My App"   # upload, then run
greenlight verify . --platform android --artifact app-release.apk --build-name "My App"
```

Only flows your app actually claims are run:

| Flow | Guideline | What runtime proves that static can't |
|------|-----------|----------------------------------------|
| `account-deletion` | §5.1.1 | The account is gone, not that a `deleteAccount` string exists |
| `restore-purchases` | §3.1.1 | "Restore Purchases" does something, rather than being a silent no-op |
| `sign-in-apple` | §4.8 | The Apple sign-in sheet appears, and the control is not dead |

A failed flow becomes a BLOCK that static analysis could never produce, with a shareable Revyl report link as evidence. `--open` follows the live session in your browser while it runs, and `--exit-code` gates CI on it.

Getting set up takes about two minutes:

```bash
brew install revylai/tap/revyl        # the device runner
revyl auth login                      # free account, no card
greenlight verify . --dry-run         # see the generated tests first
```

Unlike every other command here, `verify` is not offline: it needs the [`revyl` CLI](https://docs.revyl.com), an account, and either a registered build or a local artifact passed to `--artifact`. Revyl runs cloud simulators and emulators, so iOS takes a simulator `.app` and Android takes an `.apk`. A device `.ipa` is rejected with an explanation. [Create an account](https://app.revyl.ai/signup?utm_source=greenlight&utm_medium=readme&utm_campaign=verify).

### `greenlight guidelines`

```bash
greenlight guidelines list               # all sections
greenlight guidelines show 2.1           # a specific guideline
greenlight guidelines search "privacy"   # full-text search
```

## Output formats

| Command | Formats |
|---------|---------|
| `preflight`, `codescan` | terminal, json, sarif |
| `playscan`, `ipa`, `verify` | terminal, json |
| `scan` | terminal, json, junit |

`--output file` writes to a file instead of stdout. `--exit-code` is available on `preflight`, `playscan`, and `verify`.

Upload SARIF to GitHub code scanning and findings show up in the Security tab and inline on pull requests:

```yaml
- run: greenlight preflight . --format sarif --output greenlight.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: greenlight.sarif
```

## CI

```yaml
# GitHub Actions
- name: App Store + Play compliance
  run: greenlight preflight . --exit-code
```

That fails the job on any CRITICAL or HIGH finding, and on a scanner that crashed mid-scan. To keep the report as an artifact too:

```yaml
- run: greenlight preflight . --format json --output greenlight-report.json --exit-code
```

To gate on the runtime tier in the same step, add `--verify`. The runner needs an authenticated `revyl` CLI on PATH:

```yaml
- run: greenlight preflight . --verify --build-name "My App" --exit-code
```

## Where a static scan stops

Greenlight reads text. That is the whole of it: source files, plists, manifests, and binaries, matched against rules. It is fast and it is free because it never runs your app.

Which means there is a class of rejection it cannot see, structurally, no matter how many rules get added. A "Delete Account" button wired to nothing is the clean example. The string is in the source, so §5.1.1 is satisfied and greenlight prints GREENLIT. Apple taps the button, nothing happens, and you are rejected under §5.1.1(v), which costs you the fix plus another trip through review. Same for a Restore Purchases handler that catches its own error and returns, or a Sign in with Apple button behind a feature flag that is off in the release build.

Every one of those ships green. Nothing in this repo can catch them, because catching them requires running the app.

That is what `greenlight verify` does, and it is why [Revyl](https://revyl.com?utm_source=greenlight&utm_medium=readme&utm_campaign=static-ceiling) exists. Revyl runs mobile tests written in plain English on cloud devices, so the check is "the account is actually gone" instead of "the word `deleteAccount` appears in a file". Greenlight uses it for three flows. The same engine covers the rest of your app.

```bash
greenlight verify . --dry-run   # free, offline, shows you the tests it would run
```

Start with `--dry-run`. It generates the tests and prints them without touching a device or needing an account, so you can see whether the runtime tier is worth it before you [sign up](https://app.revyl.ai/signup?utm_source=greenlight&utm_medium=readme&utm_campaign=static-ceiling).

## Configuration (`.greenlight.yml`)

Drop a `.greenlight.yml` in your project root to tune the code scan:

```yaml
rules:
  hardcoded-ipv4:
    severity: info        # info | warn | critical
  platform-reference:
    enabled: false        # turn a rule off
ignore:
  - vendor                # skip a directory, anywhere in the tree
  - "*.generated.ts"      # skip by filename
  - src/legacy            # skip a path
```

It applies to `codescan` and to the codescan portion of `preflight`. Point at a specific file with `codescan --config path/to/.greenlight.yml`.

To silence one line rather than a whole rule, use an inline directive on the offending line or the line directly above it:

```swift
let host = "10.1.2.3" // greenlight:ignore hardcoded-ipv4
```

A bare `// greenlight:ignore` suppresses every rule on that line. Naming the rule is better: it keeps the other checks live.

## Claude Code skill

Greenlight ships as a Claude Code plugin, so Claude can run the scan, read the findings, fix them in your code, and re-run until GREENLIT.

```bash
# In Claude Code
/plugin marketplace add RevylAI/greenlight
/plugin install greenlight
```

Or copy the skill file into a project by hand:

```bash
mkdir -p .claude/skills
cp /path/to/greenlight/SKILL.md .claude/skills/greenlight.md
```

Then: *"Run greenlight preflight and fix everything until it passes."* Claude works down the severity ladder, CRITICAL first, then HIGH, WARN, and INFO, re-running after each pass.

## Codex skill

A Codex-native skill package lives at `codex-skill/`.

```bash
mkdir -p ~/.codex/skills/app-store-preflight-compliance
cp -R codex-skill/* ~/.codex/skills/app-store-preflight-compliance/
```

Then, in Codex:

```text
Use $app-store-preflight-compliance to run Greenlight preflight and fix all findings until GREENLIT.
```

## Architecture

```
greenlight
├── preflight         Run every applicable scanner, one command
│   ├── metadata      app.json / Info.plist
│   ├── codescan      24 rejection-risk rules
│   ├── privacy       Privacy manifest + Required Reason APIs
│   ├── playscan      Google Play policy (Android projects)
│   ├── ipa           Binary inspection (with --ipa)
│   └── --verify      Chain the runtime tier onto the same run
│
├── codescan          Code only, tunable via .greenlight.yml
├── privacy           Privacy manifest only
├── playscan          Google Play only, source or --apk / --aab
├── ipa               Binary only
│
├── verify            Runtime flow validation on a cloud device (Revyl)
│   ├── account-deletion   §5.1.1  the account is actually deleted
│   ├── restore-purchases  §3.1.1  Restore Purchases isn't a no-op
│   └── sign-in-apple      §4.8    the Apple sign-in sheet appears
│
├── scan              App Store Connect API checks (tiers 1-4)
│   ├── Tier 1        Metadata and completeness
│   ├── Tier 2        Content analysis
│   ├── Tier 3        Binary inspection
│   └── Tier 4        Historical pattern matching
│
├── auth              App Store Connect authentication
│   ├── login         Apple ID + 2FA session
│   ├── setup         API key configuration
│   ├── status        Current auth state
│   └── logout        Remove credentials
│
└── guidelines        Built-in Apple Review Guidelines database
    ├── list          All 5 sections with subsections
    ├── show          A specific guideline
    └── search        Full-text search
```

## Built by Revyl

Greenlight catches App Store rejections. [Revyl](https://revyl.com?utm_source=greenlight&utm_medium=readme&utm_campaign=footer) catches the bugs that get through.

It is the mobile reliability platform behind `greenlight verify`: write tests in plain English, run them on cloud devices, catch the broken flows a static scan cannot see. Greenlight itself is MIT licensed and stays that way. Revyl is where you go when you want the rest of your app covered the way those three flows are.

[Start free](https://app.revyl.ai/signup?utm_source=greenlight&utm_medium=readme&utm_campaign=footer) · [Docs](https://docs.revyl.com) · [revyl.com](https://revyl.com?utm_source=greenlight&utm_medium=readme&utm_campaign=footer)

As a little easter egg for reading this far, here is one month of Revyl free: [`ng32jDS9`](https://app.revyl.ai/signup?promo=ng32jDS9&utm_source=greenlight&utm_medium=readme&utm_campaign=easter-egg) :)
