// Package playscan checks an Android project against Google Play's Developer
// Program Policies and its published distribution deadlines.
//
// Everything here is static: it reads AndroidManifest.xml and the Gradle build
// files that ship in the repo. That is deliberate — the scan runs offline with
// no Play Console credentials — but it also bounds what the scan can see. The
// manifest in source is the *pre-merge* manifest, so permissions contributed by
// library manifests are invisible until the merge runs at build time. Findings
// here are therefore sound but not complete: what it reports is real, and a
// clean scan is not proof of a clean merged manifest. APK/AAB inspection reads
// the merged result and closes that gap.
package playscan

// Finding is a single Play policy issue. Severity strings match the unified
// preflight vocabulary ("CRITICAL", "HIGH", "WARN", "INFO").
type Finding struct {
	Severity string `json:"severity"`
	// Policy is the human-readable policy or requirement name. Play policies
	// are named rather than numbered, so this is not an Apple-style section.
	Policy string `json:"policy,omitempty"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
	// Doc links the policy page the finding is based on. Play policy pages
	// change far more often than Apple's guidelines, so every finding cites
	// the source a developer can re-read.
	Doc  string `json:"doc,omitempty"`
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`
}

// ScanResult holds the full Android scan output.
type ScanResult struct {
	ProjectPath string `json:"project_path"`
	// ManifestPath is the AndroidManifest.xml the scan read, relative to the
	// project root. Empty when no manifest was found.
	ManifestPath string `json:"manifest_path,omitempty"`
	PackageName  string `json:"package_name,omitempty"`
	TargetSDK    int    `json:"target_sdk,omitempty"`
	MinSDK       int    `json:"min_sdk,omitempty"`
	// Permissions lists every permission declared in the source manifest.
	Permissions []string  `json:"permissions,omitempty"`
	Findings    []Finding `json:"findings"`
}

const (
	sevCritical = "CRITICAL"
	sevHigh     = "HIGH"
	sevWarn     = "WARN"
	sevInfo     = "INFO"
)
