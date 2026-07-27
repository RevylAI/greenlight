package playscan

import (
	"errors"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

// skipDirs are never walked when looking for Android sources. Build outputs in
// particular contain generated and merged manifests that would otherwise be
// scanned as if a developer had written them.
var skipDirs = map[string]bool{
	"node_modules": true, ".git": true, "build": true, ".gradle": true,
	"dist": true, ".expo": true, "Pods": true, "vendor": true,
	".next": true, "DerivedData": true, "captures": true, ".idea": true,
}

// Detect reports whether the given directory looks like an Android project.
//
// A React Native or Expo project with a prebuilt android/ directory counts:
// those ship a real manifest and Gradle build, and are subject to every Play
// policy a native project is.
//
// This short-circuits on the first Android file it sees rather than reusing
// discover(), because callers use it to decide whether to run the scan at all
// and should not pay for a second full walk of the tree.
func Detect(root string) bool {
	found := false
	errStop := errors.New("found")
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == "AndroidManifest.xml" || isGradleFile(d.Name()) {
			found = true
			return errStop
		}
		return nil
	})
	return found
}

// Scan runs every Play policy rule against an Android project.
//
// A directory with no Android sources is not an error; it returns a result with
// no manifest and no findings, so the caller can run this unconditionally.
func Scan(root string) (*ScanResult, error) {
	// Findings starts non-nil so a clean scan serializes as [] rather than
	// null, which consumers parsing the JSON should not have to special-case.
	result := &ScanResult{ProjectPath: root, Findings: []Finding{}}

	manifestPath, gradlePaths := discover(root)
	if manifestPath == "" && len(gradlePaths) == 0 {
		return result, nil
	}

	relTo := func(p string) string {
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return p
		}
		return rel
	}

	gradle := parseGradleFiles(gradlePaths, relTo)

	// A Gradle build with no Android manifest and no Android plugin is some
	// other kind of JVM project. Returning empty keeps Play findings off repos
	// that never ship to Play.
	if manifestPath == "" && !gradle.HasAndroidPlugin {
		return result, nil
	}

	var manifest *Manifest
	if manifestPath != "" {
		m, err := ParseManifest(manifestPath)
		if err != nil {
			// A manifest that does not parse is worth reporting rather than
			// swallowing: the developer's build would fail on it too, and a
			// silent skip would look like a clean scan.
			result.Findings = append(result.Findings, Finding{
				Severity: sevWarn,
				Policy:   "Scan coverage",
				Title:    "AndroidManifest.xml could not be parsed",
				Detail:   "The manifest is not well-formed XML, so manifest-based policy checks were skipped: " + err.Error(),
				Fix:      "Fix the XML syntax error, then re-run the scan.",
				File:     relTo(manifestPath),
			})
			result.ManifestPath = relTo(manifestPath)
			return result, nil
		}
		manifest = m
		result.ManifestPath = relTo(manifestPath)
		result.PackageName = m.Package
		result.Permissions = m.AllPermissions()
	}

	// AGP 8 removed the manifest package attribute in favour of the Gradle
	// namespace, so fall back to it rather than showing no package at all.
	if result.PackageName == "" {
		result.PackageName = gradle.Namespace
	}

	// Gradle's android {} block wins over the manifest's <uses-sdk>, matching
	// what AGP does: the DSL value overwrites the manifest attribute at merge.
	result.TargetSDK = gradle.TargetSDK
	result.MinSDK = gradle.MinSDK
	if manifest != nil && manifest.UsesSDK != nil {
		if result.TargetSDK == 0 {
			result.TargetSDK = parseSDKInt(manifest.UsesSDK.TargetSDKVersion)
		}
		if result.MinSDK == 0 {
			result.MinSDK = parseSDKInt(manifest.UsesSDK.MinSDKVersion)
		}
	}

	ctx := &ruleContext{
		manifest:     manifest,
		gradle:       gradle,
		targetSDK:    result.TargetSDK,
		manifestFile: result.ManifestPath,
	}
	for _, rule := range allRules() {
		result.Findings = append(result.Findings, rule(ctx)...)
	}

	return result, nil
}

// discover locates the AndroidManifest.xml and Gradle scripts to read.
//
// Gradle paths come back most-specific-first so parseGradleFiles resolves the
// app module's values before any root-project ext defaults.
func discover(root string) (manifestPath string, gradlePaths []string) {
	var manifests, gradles []string

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		switch {
		case d.Name() == "AndroidManifest.xml":
			manifests = append(manifests, path)
		case isGradleFile(d.Name()), isVersionCatalog(d.Name()),
			isConventionPlugin(path), isGradleProperties(d.Name()):
			gradles = append(gradles, path)
		}
		return nil
	})

	sort.SliceStable(manifests, func(i, j int) bool {
		si, sj := manifestScore(manifests[i]), manifestScore(manifests[j])
		if si != sj {
			return si > sj
		}
		return manifests[i] < manifests[j]
	})

	// The manifest is chosen first so Gradle ranking can be tied to the module
	// that manifest belongs to. Without that link, a repo whose app module is
	// not named "app" ranks its build files no higher than a library's, and the
	// scan can report a library module's targetSdk as the app's.
	if len(manifests) > 0 {
		manifestPath = selectAppManifest(manifests)
	}
	appModule := moduleDirOf(manifestPath)

	sort.Slice(gradles, func(i, j int) bool {
		si, sj := gradleScore(gradles[i], appModule), gradleScore(gradles[j], appModule)
		if si != sj {
			return si > sj
		}
		return gradles[i] < gradles[j]
	})

	return manifestPath, gradles
}

// moduleDirOf returns the Gradle module directory a manifest belongs to, i.e.
// the path above its source set. Empty when there is no manifest to anchor to.
func moduleDirOf(manifestPath string) string {
	if manifestPath == "" {
		return ""
	}
	p := filepath.ToSlash(manifestPath)
	if i := strings.Index(p, "/src/"); i > 0 {
		return p[:i]
	}
	return filepath.ToSlash(filepath.Dir(p))
}

// selectAppManifest picks the shipped application's manifest out of every
// candidate in the repo.
//
// Path shape alone is not enough: multi-module projects routinely name the app
// module something other than "app" (AnkiDroid's is "AnkiDroid"), which lets a
// benchmark or library module win on path score and silently hide the real
// app's permissions. The launcher activity is the definitive signal, so
// candidates are parsed and one declaring MAIN/LAUNCHER wins outright.
func selectAppManifest(candidates []string) string {
	best, bestScore := candidates[0], -1<<30
	for _, path := range candidates {
		score := manifestScore(path)
		if m, err := ParseManifest(path); err == nil && m.HasLauncherActivity() {
			score += 1000
		}
		if score > bestScore {
			best, bestScore = path, score
		}
	}
	return best
}

// manifestScore ranks candidate manifests by path shape, used to break ties
// once the launcher-activity signal has been applied.
func manifestScore(path string) int {
	p := filepath.ToSlash(path)
	score := 0
	if strings.Contains(p, "/src/main/") {
		score += 10
	}
	if strings.Contains(p, "/app/") {
		score += 5
	}
	// Non-shipping source sets never hold the app's real configuration.
	for _, sourceSet := range []string{"/src/debug/", "/src/androidTest/", "/src/test/", "/src/benchmark/", "/src/nightly/"} {
		if strings.Contains(p, sourceSet) {
			score -= 20
		}
	}
	// Modules that exist to measure or test the app, not to ship it.
	for _, module := range []string{"/baselineprofile/", "/benchmark/", "/macrobenchmark/", "/lint/", "/testlib/"} {
		if strings.Contains(p, module) {
			score -= 30
		}
	}
	// Shallower manifests are more likely to be the application's own.
	score -= strings.Count(p, "/")
	return score
}

// gradleScore ranks build files by how authoritative they are for the shipped
// application's configuration, most authoritative first.
//
// The app module's own android {} block wins, then the convention plugin that
// configures application modules, then other build-logic sources, then the
// version catalog those files interpolate from.
func gradleScore(path string, appModule string) int {
	p := filepath.ToSlash(path)
	base := strings.ToLower(filepath.Base(p))
	score := 0

	// A build file sitting in the same module as the app's manifest is the
	// app's own, whatever that module happens to be called.
	if appModule != "" && strings.HasPrefix(p, appModule+"/") {
		score += 20
	}

	switch {
	case isGradleProperties(base):
		// Properties only hold values other files reference.
		score += 2
	case isVersionCatalog(base):
		// A catalog only holds the values other files reference, so it is the
		// last resort rather than a statement about the app module.
		score += 2
	case isConventionPlugin(path):
		score += 6
		// The plugin applied to application modules is the one whose targetSdk
		// actually ships; library and test plugins configure other things.
		if strings.Contains(strings.ToLower(base), "application") {
			score += 4
		}
		if strings.Contains(strings.ToLower(base), "library") || strings.Contains(strings.ToLower(base), "test") {
			score -= 4
		}
	case strings.HasPrefix(base, "build.gradle"):
		score += 5
		// Fallback for the conventional module name when there is no manifest
		// to anchor to (a Gradle-only scan).
		if appModule == "" && strings.Contains(p, "/app/") {
			score += 10
		}
	case strings.HasPrefix(base, "settings.gradle"):
		score -= 5
	}
	return score
}
