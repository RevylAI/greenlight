package preflight

import (
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/RevylAI/greenlight/internal/playscan"
)

// iosSkipDirs mirrors the directories the other scanners ignore, so a vendored
// dependency's Xcode project cannot make a repo look like an iOS app.
var iosSkipDirs = map[string]bool{
	"node_modules": true, ".git": true, "build": true, ".gradle": true,
	"dist": true, ".expo": true, "Pods": true, "vendor": true,
	".next": true, "DerivedData": true, ".idea": true,
}

// DetectPlatforms reports which app platforms a project targets.
//
// This exists to keep store-specific findings off projects that do not ship to
// that store: an Android-only repo should never be told it is missing an Apple
// privacy manifest. Detection is deliberately generous on the iOS side, since
// the cost of a missed iOS signal (silently skipping the Apple checks) is far
// worse than the cost of running them on a repo that does not need them.
func DetectPlatforms(root string) (ios, android bool) {
	android = playscan.Detect(root)
	ios = detectIOS(root)
	return ios, android
}

func detectIOS(root string) bool {
	found := false
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if iosSkipDirs[name] {
				return filepath.SkipDir
			}
			// An .xcodeproj / .xcworkspace bundle is itself a directory.
			if strings.HasSuffix(name, ".xcodeproj") || strings.HasSuffix(name, ".xcworkspace") {
				found = true
				return filepath.SkipAll
			}
			return nil
		}

		lower := strings.ToLower(name)
		switch {
		case strings.EqualFold(name, "Info.plist"),
			strings.EqualFold(name, "Podfile"),
			strings.EqualFold(name, "Package.swift"),
			strings.EqualFold(name, "project.pbxproj"),
			strings.HasSuffix(name, ".xcprivacy"),
			strings.HasSuffix(lower, ".swift"),
			// Objective-C sources: codescan reads these for private-API use, so
			// missing them would silently drop real Apple findings.
			strings.HasSuffix(lower, ".m"),
			strings.HasSuffix(lower, ".mm"),
			strings.HasSuffix(lower, ".h"),
			strings.HasSuffix(lower, ".xcodeproj"):
			found = true
			return filepath.SkipAll
		}

		// An Expo / React Native config ships to the App Store even when the
		// repo holds no native iOS sources. All four spellings count; missing
		// one classifies a cross-platform app as Android-only.
		switch lower {
		case "app.json", "app.config.js", "app.config.ts", "app.config.json":
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}
