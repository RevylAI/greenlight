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
		{"xr", "android.software.xr.immersive", FormFactorXR},
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
