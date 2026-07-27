package playscan

import (
	"encoding/xml"
	"os"
	"strconv"
	"strings"
)

// Manifest is the subset of AndroidManifest.xml the policy rules need.
//
// Attribute tags intentionally omit the android XML namespace. Go's decoder
// matches an unqualified `,attr` tag against any namespace, which keeps parsing
// working on manifests that bind the android prefix unusually or omit the
// xmlns declaration entirely (both appear in real generated manifests).
type Manifest struct {
	XMLName     xml.Name         `xml:"manifest"`
	Package     string           `xml:"package,attr"`
	Permissions []UsesPermission `xml:"uses-permission"`
	// PermissionsSDK23 covers <uses-permission-sdk-23>, which grants the same
	// policy obligations as a plain <uses-permission>.
	PermissionsSDK23 []UsesPermission `xml:"uses-permission-sdk-23"`
	UsesSDK          *UsesSDK         `xml:"uses-sdk"`
	Application      *Application     `xml:"application"`
}

type UsesPermission struct {
	Name string `xml:"name,attr"`
}

type UsesSDK struct {
	MinSDKVersion    string `xml:"minSdkVersion,attr"`
	TargetSDKVersion string `xml:"targetSdkVersion,attr"`
}

type Application struct {
	Name                 string      `xml:"name,attr"`
	Debuggable           string      `xml:"debuggable,attr"`
	AllowBackup          string      `xml:"allowBackup,attr"`
	UsesCleartextTraffic string      `xml:"usesCleartextTraffic,attr"`
	NetworkSecurityConf  string      `xml:"networkSecurityConfig,attr"`
	Activities           []Component `xml:"activity"`
	ActivityAliases      []Component `xml:"activity-alias"`
	Services             []Component `xml:"service"`
	Receivers            []Component `xml:"receiver"`
	Providers            []Component `xml:"provider"`
}

// Component covers the four manifest component types. Only the attributes the
// policy rules read are modelled.
type Component struct {
	Name              string         `xml:"name,attr"`
	Exported          string         `xml:"exported,attr"`
	Permission        string         `xml:"permission,attr"`
	ForegroundSvcType string         `xml:"foregroundServiceType,attr"`
	IntentFilters     []IntentFilter `xml:"intent-filter"`
}

type IntentFilter struct {
	Actions []struct {
		Name string `xml:"name,attr"`
	} `xml:"action"`
	Categories []struct {
		Name string `xml:"name,attr"`
	} `xml:"category"`
}

// HasLauncherActivity reports whether the manifest declares the app's launcher
// entry point. In a multi-module repo this is what distinguishes the shipped
// application's manifest from those of its libraries, benchmark harnesses, and
// test modules — none of which carry the app's permissions.
func (m *Manifest) HasLauncherActivity() bool {
	if m.Application == nil {
		return false
	}
	for _, comp := range append(append([]Component{}, m.Application.Activities...), m.Application.ActivityAliases...) {
		for _, f := range comp.IntentFilters {
			mainAction, launcherCategory := false, false
			for _, a := range f.Actions {
				if a.Name == "android.intent.action.MAIN" {
					mainAction = true
				}
			}
			for _, c := range f.Categories {
				if c.Name == "android.intent.category.LAUNCHER" {
					launcherCategory = true
				}
			}
			if mainAction && launcherCategory {
				return true
			}
		}
	}
	return false
}

// HasIntentFilter reports whether the component declares any intent filter,
// which is what makes android:exported mandatory from API 31.
func (c Component) HasIntentFilter() bool { return len(c.IntentFilters) > 0 }

// ParseManifest reads and decodes an AndroidManifest.xml.
func ParseManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := xml.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// AllPermissions returns every declared permission name, de-duplicated and in
// declaration order.
func (m *Manifest) AllPermissions() []string {
	seen := make(map[string]bool)
	var out []string
	for _, p := range append(append([]UsesPermission{}, m.Permissions...), m.PermissionsSDK23...) {
		name := strings.TrimSpace(p.Name)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// HasPermission reports whether the manifest declares the given permission.
// Matching is on the full name, so "android.permission.READ_SMS" does not
// match "com.example.READ_SMS".
func (m *Manifest) HasPermission(name string) bool {
	for _, p := range m.AllPermissions() {
		if p == name {
			return true
		}
	}
	return false
}

// Components returns every component across all four types.
func (a *Application) Components() []Component {
	if a == nil {
		return nil
	}
	var out []Component
	out = append(out, a.Activities...)
	out = append(out, a.ActivityAliases...)
	out = append(out, a.Services...)
	out = append(out, a.Receivers...)
	out = append(out, a.Providers...)
	return out
}

// attrIsTrue reports whether a manifest boolean attribute is literally true.
//
// Manifest booleans are frequently resource references ("@bool/is_debug") or
// Gradle manifest placeholders ("${debuggable}"), whose value is not knowable
// without running the build. Those resolve to false here so the scan never
// invents a finding it cannot stand behind.
func attrIsTrue(v string) bool {
	return strings.EqualFold(strings.TrimSpace(v), "true")
}

// attrIsSet reports whether an attribute was present at all, distinguishing
// android:exported="false" from a missing android:exported.
func attrIsSet(v string) bool { return strings.TrimSpace(v) != "" }

// parseSDKInt reads an SDK level attribute. Values can be a plain integer, a
// codename for preview releases, or a Gradle placeholder; only integers are
// usable and everything else returns 0 ("unknown").
func parseSDKInt(v string) int {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 {
		return 0
	}
	return n
}
