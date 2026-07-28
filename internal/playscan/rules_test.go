package playscan

import "testing"

// --- review regression: form factor -------------------------------------

// Play publishes a separate target API schedule per form factor, so a Wear, TV,
// Automotive, or XR app must not get the phone track's blocking finding.
func TestTargetAPILevelRespectsFormFactor(t *testing.T) {
	cases := []struct {
		name    string
		feature string
		want    FormFactor
	}{
		{"wear", "android.hardware.type.watch", FormFactorWear},
		{"tv", "android.software.leanback", FormFactorTV},
		{"automotive", "android.hardware.type.automotive", FormFactorAutomotive},
		{"xr spatial", "android.software.xr.api.spatial", FormFactorXR},
		{"xr openxr", "android.software.xr.api.openxr", FormFactorXR},
		{"xr hardware input", "android.hardware.xr.input.controller", FormFactorXR},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &ruleContext{
				manifest: &Manifest{
					UsesFeatures: []UsesFeature{{Name: tc.feature}},
				},
				gradle:       &GradleInfo{},
				targetSDK:    33,
				manifestFile: "AndroidManifest.xml",
			}
			if got := c.formFactor(); got != tc.want {
				t.Fatalf("formFactor = %q, want %q", got, tc.want)
			}
			findings := ruleTargetAPILevel(c)
			if len(findings) != 1 {
				t.Fatalf("want 1 finding, got %d", len(findings))
			}
			if findings[0].Severity != sevWarn {
				t.Errorf("severity = %v, want WARN (a non-phone app must not be gated on the phone schedule)", findings[0].Severity)
			}
		})
	}
}

// A phone app keeps the blocking behaviour.
func TestTargetAPILevelPhoneStillBlocks(t *testing.T) {
	c := &ruleContext{
		manifest:     &Manifest{},
		gradle:       &GradleInfo{},
		targetSDK:    33,
		manifestFile: "AndroidManifest.xml",
	}
	findings := ruleTargetAPILevel(c)
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != sevCritical {
		t.Errorf("severity = %v, want CRITICAL for a phone app below the floor", findings[0].Severity)
	}
}

// A non-phone app already at or above the phone requirement needs no finding.
func TestTargetAPILevelFormFactorCleanWhenCurrent(t *testing.T) {
	c := &ruleContext{
		manifest: &Manifest{
			UsesFeatures: []UsesFeature{{Name: "android.hardware.type.watch"}},
		},
		gradle:    &GradleInfo{},
		targetSDK: requiredTargetSDKNew,
	}
	if findings := ruleTargetAPILevel(c); len(findings) != 0 {
		t.Errorf("want no findings, got %d: %s", len(findings), findings[0].Title)
	}
}

// XR is matched by namespace, not by an exact constant name. The rule shipped
// with two invented names (android.software.xr.immersive,
// android.hardware.xr.head_tracking) that no real XR app declares, so no XR
// package ever matched and they kept getting the phone track's blocking
// finding. No XR constant appears in android.jar for API 34-36, so the
// namespace is what can actually be relied on.
func TestFormFactorMatchesXRByNamespace(t *testing.T) {
	xr := []string{
		"android.software.xr.api.spatial",
		"android.software.xr.api.openxr",
		"android.hardware.xr.input.controller",
		"android.software.xr.something.added.later",
	}
	for _, name := range xr {
		m := &Manifest{UsesFeatures: []UsesFeature{{Name: name}}}
		if got := m.FormFactor(); got != FormFactorXR {
			t.Errorf("%s: FormFactor = %q, want %q", name, got, FormFactorXR)
		}
	}

	// The namespace must not swallow unrelated features that merely contain
	// "xr", nor an XR feature the app says it does not require.
	notXR := []string{
		"android.hardware.camera",
		"android.software.xrated", // not the xr namespace: no dot after xr
		"com.example.xr.custom",
	}
	for _, name := range notXR {
		m := &Manifest{UsesFeatures: []UsesFeature{{Name: name}}}
		if got := m.FormFactor(); got != FormFactorPhone {
			t.Errorf("%s: FormFactor = %q, want phone", name, got)
		}
	}

	optional := &Manifest{UsesFeatures: []UsesFeature{
		{Name: "android.software.xr.api.spatial", Required: "false"},
	}}
	if got := optional.FormFactor(); got != FormFactorPhone {
		t.Errorf("optional XR feature: FormFactor = %q, want phone", got)
	}
}
