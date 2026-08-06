package codescan

import (
	"os"
	"path/filepath"
)

// unityGeneratedDirNames are directories the Unity editor (re)generates on every
// import or build. They hold engine caches and IL artifacts — never shippable
// source — and in a mature project they dwarf Assets/ by an order of magnitude,
// so walking them wrecks scan time and drowns findings in vendored engine code.
var unityGeneratedDirNames = []string{
	"Library", "Temp", "Logs", "obj", "UserSettings",
}

// UnityGeneratedDirs returns the set of Unity-generated directory names to skip
// under root, or nil when root is not a Unity project. Detection keys off
// ProjectSettings/ProjectSettings.asset, which every Unity project has and
// nothing else does — a bare directory named "Library" is perfectly normal in
// other ecosystems, so the skip list must never apply outside Unity.
func UnityGeneratedDirs(root string) map[string]bool {
	if !IsUnityProject(root) {
		return nil
	}
	dirs := make(map[string]bool, len(unityGeneratedDirNames))
	for _, d := range unityGeneratedDirNames {
		dirs[d] = true
	}
	return dirs
}

// IsUnityProject reports whether root is a Unity project directory.
func IsUnityProject(root string) bool {
	_, err := os.Stat(filepath.Join(root, "ProjectSettings", "ProjectSettings.asset"))
	return err == nil
}
