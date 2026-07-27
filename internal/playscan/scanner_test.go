package playscan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeProject materializes a map of relative paths to contents in a temp dir.
func writeProject(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", rel, err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	return root
}

// findByPolicy returns the first finding for a policy, or nil.
func findByPolicy(findings []Finding, policy string) *Finding {
	for i := range findings {
		if findings[i].Policy == policy {
			return &findings[i]
		}
	}
	return nil
}

func countByPolicy(findings []Finding, policy string) int {
	n := 0
	for _, f := range findings {
		if f.Policy == policy {
			n++
		}
	}
	return n
}

// freezeClock pins the deadline clock so day-count wording is deterministic.
func freezeClock(t *testing.T, at time.Time) {
	t.Helper()
	prev := now
	now = func() time.Time { return at }
	t.Cleanup(func() { now = prev })
}

const manifestHeader = `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app">`

func TestParseManifestReadsNamespacedAttributes(t *testing.T) {
	root := writeProject(t, map[string]string{
		"app/src/main/AndroidManifest.xml": manifestHeader + `
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.READ_SMS" />
    <uses-permission-sdk-23 android:name="android.permission.CAMERA" />
    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="33" />
    <application android:label="App" android:debuggable="true">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
            </intent-filter>
        </activity>
        <service android:name=".SyncService" android:foregroundServiceType="dataSync" />
    </application>
</manifest>`,
	})

	m, err := ParseManifest(filepath.Join(root, "app/src/main/AndroidManifest.xml"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if m.Package != "com.example.app" {
		t.Errorf("package = %q, want com.example.app", m.Package)
	}
	if !m.HasPermission("android.permission.READ_SMS") {
		t.Error("READ_SMS not detected")
	}
	// uses-permission-sdk-23 carries the same obligations as uses-permission.
	if !m.HasPermission("android.permission.CAMERA") {
		t.Error("uses-permission-sdk-23 CAMERA not detected")
	}
	if m.HasPermission("android.permission.READ_CONTACTS") {
		t.Error("undeclared permission reported as present")
	}
	if got := parseSDKInt(m.UsesSDK.TargetSDKVersion); got != 33 {
		t.Errorf("targetSdkVersion = %d, want 33", got)
	}
	if !attrIsTrue(m.Application.Debuggable) {
		t.Error("debuggable attribute not read")
	}
	if len(m.Application.Services) != 1 || m.Application.Services[0].ForegroundSvcType != "dataSync" {
		t.Errorf("foregroundServiceType not read: %+v", m.Application.Services)
	}
	if !m.Application.Activities[0].HasIntentFilter() {
		t.Error("intent-filter not read")
	}
}

func TestHasPermissionRequiresExactName(t *testing.T) {
	root := writeProject(t, map[string]string{
		"app/src/main/AndroidManifest.xml": manifestHeader + `
    <uses-permission android:name="com.example.app.READ_SMS" />
    <application />
</manifest>`,
	})
	m, err := ParseManifest(filepath.Join(root, "app/src/main/AndroidManifest.xml"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// A custom permission that merely ends in READ_SMS must not trip the
	// restricted-permission rule.
	if m.HasPermission("android.permission.READ_SMS") {
		t.Error("custom permission matched the platform permission")
	}
}

func TestGradleTargetSDKForms(t *testing.T) {
	cases := []struct {
		name string
		line string
		want int
	}{
		{"groovy bare", "targetSdkVersion 34", 34},
		{"groovy paren", "targetSdkVersion(34)", 34},
		{"kts assign", "targetSdk = 35", 35},
		{"kts short", "targetSdk 36", 36},
		{"kts set", "targetSdk.set(33)", 33},
		{"quoted", `targetSdkVersion "34"`, 34},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := writeProject(t, map[string]string{
				"app/build.gradle": "android {\n    defaultConfig {\n        " + tc.line + "\n    }\n}\n",
			})
			res, err := Scan(root)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if res.TargetSDK != tc.want {
				t.Errorf("TargetSDK = %d, want %d", res.TargetSDK, tc.want)
			}
		})
	}
}

// An interpolated targetSdk in the app module must resolve from the root ext
// block, which is the standard Expo / React Native layout.
func TestGradleTargetSDKFromRootExtBlock(t *testing.T) {
	root := writeProject(t, map[string]string{
		"android/build.gradle": `buildscript {
    ext {
        minSdkVersion = 24
        targetSdkVersion = 34
    }
}`,
		"android/app/build.gradle": `android {
    defaultConfig {
        targetSdkVersion rootProject.ext.targetSdkVersion
    }
}`,
	})
	res, err := Scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if res.TargetSDK != 34 {
		t.Errorf("TargetSDK = %d, want 34 resolved from the root ext block", res.TargetSDK)
	}
}

func TestGradleIgnoresCommentedDependency(t *testing.T) {
	root := writeProject(t, map[string]string{
		"app/build.gradle": `dependencies {
    // implementation 'com.android.billingclient:billing:5.0.0'
    implementation 'androidx.core:core-ktx:1.13.0'
}`,
	})
	res, err := Scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if f := findByPolicy(res.Findings, "Play Billing Library"); f != nil {
		t.Errorf("commented-out billing dependency produced a finding: %s", f.Title)
	}
}

func TestTargetAPILevelSeverityTiers(t *testing.T) {
	freezeClock(t, time.Date(2026, time.July, 27, 0, 0, 0, 0, time.UTC))

	cases := []struct {
		targetSDK    int
		wantSeverity string
		wantFinding  bool
	}{
		{34, sevCritical, true}, // below the existing-app floor
		{35, sevHigh, true},     // meets the floor, below the new-submission bar
		{36, "", false},         // compliant
		{37, "", false},         // ahead of the requirement
	}
	for _, tc := range cases {
		root := writeProject(t, map[string]string{
			"app/build.gradle": "android { defaultConfig { targetSdk = " + itoa(tc.targetSDK) + " } }",
		})
		res, err := Scan(root)
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		f := findByPolicy(res.Findings, "Target API level")
		if !tc.wantFinding {
			if f != nil {
				t.Errorf("targetSdk %d: unexpected finding %q", tc.targetSDK, f.Title)
			}
			continue
		}
		if f == nil {
			t.Errorf("targetSdk %d: expected a finding, got none", tc.targetSDK)
			continue
		}
		if f.Severity != tc.wantSeverity {
			t.Errorf("targetSdk %d: severity = %s, want %s", tc.targetSDK, f.Severity, tc.wantSeverity)
		}
		if !strings.Contains(f.Detail, "35 days left") {
			t.Errorf("targetSdk %d: detail missing the day countdown: %s", tc.targetSDK, f.Detail)
		}
	}
}

func TestDeadlinePhraseAfterDeadline(t *testing.T) {
	freezeClock(t, time.Date(2026, time.September, 15, 0, 0, 0, 0, time.UTC))
	got := deadlinePhrase(targetAPIDeadline)
	if !strings.Contains(got, "has passed") {
		t.Errorf("after the deadline the phrase should say it passed, got %q", got)
	}
}

func TestUnresolvableTargetSDKWarnsRatherThanPasses(t *testing.T) {
	root := writeProject(t, map[string]string{
		"app/build.gradle": `android {
    defaultConfig {
        targetSdkVersion libs.versions.targetSdk.get().toInteger()
    }
}`,
	})
	res, err := Scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	f := findByPolicy(res.Findings, "Target API level")
	if f == nil || f.Severity != sevWarn {
		t.Fatalf("an unresolvable targetSdk must warn rather than silently pass, got %+v", f)
	}
}

func TestRestrictedPermissionsFire(t *testing.T) {
	root := writeProject(t, map[string]string{
		"app/build.gradle": "android { defaultConfig { targetSdk = 36 } }",
		"app/src/main/AndroidManifest.xml": manifestHeader + `
    <uses-permission android:name="android.permission.READ_SMS" />
    <uses-permission android:name="android.permission.READ_CALL_LOG" />
    <uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.QUERY_ALL_PACKAGES" />
    <uses-permission android:name="android.permission.ACCESS_BACKGROUND_LOCATION" />
    <application />
</manifest>`,
	})
	res, err := Scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	for _, policy := range []string{
		"SMS and Call Log permissions", "All files access",
		"Package visibility", "Background location",
	} {
		if findByPolicy(res.Findings, policy) == nil {
			t.Errorf("expected a finding for policy %q", policy)
		}
	}
	// SMS and Call Log are separate entries under one policy name.
	if n := countByPolicy(res.Findings, "SMS and Call Log permissions"); n != 2 {
		t.Errorf("SMS + Call Log should produce 2 findings, got %d", n)
	}
	// Every finding must cite a policy page.
	for _, f := range res.Findings {
		if f.Doc == "" {
			t.Errorf("finding %q has no Doc link", f.Title)
		}
	}
}

// The photo/video policy only binds at targetSdk 33+, so a lower target must
// not produce the finding.
func TestPhotoPermissionGatedByTargetSDK(t *testing.T) {
	manifest := manifestHeader + `
    <uses-permission android:name="android.permission.READ_MEDIA_IMAGES" />
    <application />
</manifest>`

	low := writeProject(t, map[string]string{
		"app/build.gradle":                 "android { defaultConfig { targetSdk = 32 } }",
		"app/src/main/AndroidManifest.xml": manifest,
	})
	res, err := Scan(low)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if f := findByPolicy(res.Findings, "Photo and Video Permissions"); f != nil {
		t.Error("photo permission policy fired below targetSdk 33")
	}

	high := writeProject(t, map[string]string{
		"app/build.gradle":                 "android { defaultConfig { targetSdk = 36 } }",
		"app/src/main/AndroidManifest.xml": manifest,
	})
	res, err = Scan(high)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if f := findByPolicy(res.Findings, "Photo and Video Permissions"); f == nil {
		t.Error("photo permission policy did not fire at targetSdk 36")
	}
}

func TestForegroundServiceTypeMissingPermission(t *testing.T) {
	root := writeProject(t, map[string]string{
		"app/build.gradle": "android { defaultConfig { targetSdk = 36 } }",
		"app/src/main/AndroidManifest.xml": manifestHeader + `
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
    <application>
        <service android:name=".LocationService" android:foregroundServiceType="location" />
    </application>
</manifest>`,
	})
	res, err := Scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	f := findByPolicy(res.Findings, "Foreground services")
	if f == nil {
		t.Fatal("missing FOREGROUND_SERVICE_LOCATION was not reported")
	}
	if f.Severity != sevCritical {
		t.Errorf("severity = %s, want CRITICAL (it crashes at startForeground)", f.Severity)
	}
	if !strings.Contains(f.Detail, "FOREGROUND_SERVICE_LOCATION") {
		t.Errorf("detail should name the missing permission: %s", f.Detail)
	}
}

func TestForegroundServiceTypeWithPermissionIsClean(t *testing.T) {
	root := writeProject(t, map[string]string{
		"app/build.gradle": "android { defaultConfig { targetSdk = 36 } }",
		"app/src/main/AndroidManifest.xml": manifestHeader + `
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE_LOCATION" />
    <application>
        <service android:name=".LocationService" android:foregroundServiceType="location" />
    </application>
</manifest>`,
	})
	res, err := Scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if f := findByPolicy(res.Findings, "Foreground services"); f != nil {
		t.Errorf("declared permission should satisfy the rule, got %q", f.Title)
	}
}

// Multiple pipe-separated types each need their own permission.
func TestForegroundServiceMultipleTypes(t *testing.T) {
	root := writeProject(t, map[string]string{
		"app/build.gradle": "android { defaultConfig { targetSdk = 36 } }",
		"app/src/main/AndroidManifest.xml": manifestHeader + `
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE_LOCATION" />
    <application>
        <service android:name=".Svc" android:foregroundServiceType="location|camera" />
    </application>
</manifest>`,
	})
	res, err := Scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	var sawCamera bool
	for _, f := range res.Findings {
		if f.Policy == "Foreground services" && strings.Contains(f.Detail, "FOREGROUND_SERVICE_CAMERA") {
			sawCamera = true
		}
	}
	if !sawCamera {
		t.Fatalf("the camera half of location|camera was not checked: %+v", res.Findings)
	}
	// location's permission is declared, so only camera should be reported.
	for _, f := range res.Findings {
		if f.Policy == "Foreground services" && strings.Contains(f.Detail, "FOREGROUND_SERVICE_LOCATION") {
			t.Errorf("location permission is declared but was still reported: %s", f.Detail)
		}
	}
}

// Every foreground service needs the base FOREGROUND_SERVICE permission, not
// just the type-specific one. Checking only the type-specific permissions
// missed this case entirely.
func TestForegroundServiceBasePermissionRequired(t *testing.T) {
	root := writeProject(t, map[string]string{
		"app/build.gradle": "android { defaultConfig { targetSdk = 36 } }",
		"app/src/main/AndroidManifest.xml": manifestHeader + `
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE_LOCATION" />
    <application>
        <service android:name=".Svc" android:foregroundServiceType="location" />
    </application>
</manifest>`,
	})
	res, err := Scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	var sawBase bool
	for _, f := range res.Findings {
		if f.Policy == "Foreground services" && strings.Contains(f.Title, "without the FOREGROUND_SERVICE permission") {
			sawBase = true
			if f.Severity != sevCritical {
				t.Errorf("severity = %s, want CRITICAL", f.Severity)
			}
		}
	}
	if !sawBase {
		t.Error("missing base FOREGROUND_SERVICE permission was not reported")
	}
}

// BIND_* permissions are never requested via <uses-permission>; the framework
// requires them as the component's android:permission. Checking only the
// uses-permission list meant these rules could never fire.
func TestComponentBoundPermissionsDetected(t *testing.T) {
	root := writeProject(t, map[string]string{
		"app/build.gradle": "android { defaultConfig { targetSdk = 36 } }",
		"app/src/main/AndroidManifest.xml": manifestHeader + `
    <application>
        <service android:name=".A11yService"
                 android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE" />
        <service android:name=".Vpn"
                 android:permission="android.permission.BIND_VPN_SERVICE" />
        <receiver android:name=".Admin"
                  android:permission="android.permission.BIND_DEVICE_ADMIN" />
    </application>
</manifest>`,
	})
	res, err := Scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, policy := range []string{"Accessibility API", "VPN Service", "Device admin"} {
		if findByPolicy(res.Findings, policy) == nil {
			t.Errorf("component-declared permission for %q was not detected", policy)
		}
	}
}

// The app module is frequently not named "app", so Gradle files must be ranked
// against the module the selected manifest belongs to. Otherwise a library
// module's targetSdk can be reported as the app's.
func TestGradleSelectionFollowsAppModule(t *testing.T) {
	root := writeProject(t, map[string]string{
		// A library module that would otherwise win on path score.
		"app/build.gradle": "android { defaultConfig { targetSdk = 30 } }",
		"app/src/main/AndroidManifest.xml": manifestHeader + `
    <application />
</manifest>`,
		// The real application module, named after the product.
		"MyProduct/build.gradle": "android { defaultConfig { targetSdk = 36 } }",
		"MyProduct/src/main/AndroidManifest.xml": manifestHeader + `
    <application>
        <activity android:name=".Main" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>`,
	})
	res, err := Scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if res.TargetSDK != 36 {
		t.Errorf("TargetSDK = %d, want 36 from the app module's own build.gradle", res.TargetSDK)
	}
	if f := findByPolicy(res.Findings, "Target API level"); f != nil {
		t.Errorf("app module targets 36 and is compliant, got %q", f.Title)
	}
}

func TestDebuggableIsCritical(t *testing.T) {
	root := writeProject(t, map[string]string{
		"app/build.gradle": "android { defaultConfig { targetSdk = 36 } }",
		"app/src/main/AndroidManifest.xml": manifestHeader + `
    <application android:debuggable="true" />
</manifest>`,
	})
	res, err := Scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	f := findByPolicy(res.Findings, "Malicious Behavior")
	if f == nil || f.Severity != sevCritical {
		t.Fatalf("debuggable=true must be CRITICAL, got %+v", f)
	}
}

// A placeholder or resource reference is not knowable statically and must not
// be reported as a violation.
func TestDebuggablePlaceholderIsNotReported(t *testing.T) {
	for _, value := range []string{"${debuggable}", "@bool/is_debuggable", "false"} {
		root := writeProject(t, map[string]string{
			"app/build.gradle": "android { defaultConfig { targetSdk = 36 } }",
			"app/src/main/AndroidManifest.xml": manifestHeader + `
    <application android:debuggable="` + value + `" />
</manifest>`,
		})
		res, err := Scan(root)
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if f := findByPolicy(res.Findings, "Malicious Behavior"); f != nil {
			t.Errorf("debuggable=%q should not be reported, got %q", value, f.Title)
		}
	}
}

func TestExportedMissingOnIntentFilterComponent(t *testing.T) {
	root := writeProject(t, map[string]string{
		"app/build.gradle": "android { defaultConfig { targetSdk = 36 } }",
		"app/src/main/AndroidManifest.xml": manifestHeader + `
    <application>
        <activity android:name=".MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
            </intent-filter>
        </activity>
        <receiver android:name=".BootReceiver" android:exported="false">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
            </intent-filter>
        </receiver>
    </application>
</manifest>`,
	})
	res, err := Scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	f := findByPolicy(res.Findings, "Manifest requirements")
	if f == nil {
		t.Fatal("missing android:exported was not reported")
	}
	if !strings.Contains(f.Detail, ".MainActivity") {
		t.Errorf("should name the offending component: %s", f.Detail)
	}
	// The receiver sets exported explicitly, so it must not be listed.
	if strings.Contains(f.Detail, ".BootReceiver") {
		t.Errorf("component with an explicit exported was listed: %s", f.Detail)
	}
}

func TestExportedRuleSkippedBelowAPI31(t *testing.T) {
	root := writeProject(t, map[string]string{
		"app/build.gradle": "android { defaultConfig { targetSdk = 30 } }",
		"app/src/main/AndroidManifest.xml": manifestHeader + `
    <application>
        <activity android:name=".MainActivity">
            <intent-filter><action android:name="android.intent.action.MAIN" /></intent-filter>
        </activity>
    </application>
</manifest>`,
	})
	res, err := Scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if f := findByPolicy(res.Findings, "Manifest requirements"); f != nil {
		t.Error("the exported requirement does not bind below API 31")
	}
}

func TestAdvertisingIDPermissionMissing(t *testing.T) {
	root := writeProject(t, map[string]string{
		"app/build.gradle": `android { defaultConfig { targetSdk = 36 } }
dependencies {
    implementation 'com.google.android.gms:play-services-ads:23.0.0'
}`,
		"app/src/main/AndroidManifest.xml": manifestHeader + `
    <application />
</manifest>`,
	})
	res, err := Scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	f := findByPolicy(res.Findings, "Advertising ID")
	if f == nil {
		t.Fatal("ads SDK without AD_ID was not reported")
	}
	if f.Line == 0 {
		t.Error("finding should point at the dependency line")
	}
}

func TestAdvertisingIDPermissionPresentIsClean(t *testing.T) {
	root := writeProject(t, map[string]string{
		"app/build.gradle": `android { defaultConfig { targetSdk = 36 } }
dependencies { implementation 'com.google.android.gms:play-services-ads:23.0.0' }`,
		"app/src/main/AndroidManifest.xml": manifestHeader + `
    <uses-permission android:name="com.google.android.gms.permission.AD_ID" />
    <application />
</manifest>`,
	})
	res, err := Scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if f := findByPolicy(res.Findings, "Advertising ID"); f != nil {
		t.Errorf("AD_ID is declared, expected no finding, got %q", f.Title)
	}
}

func TestBillingVersionBelowSupported(t *testing.T) {
	freezeClock(t, time.Date(2026, time.July, 27, 0, 0, 0, 0, time.UTC))
	root := writeProject(t, map[string]string{
		"app/build.gradle": `android { defaultConfig { targetSdk = 36 } }
dependencies { implementation 'com.android.billingclient:billing:7.1.1' }`,
	})
	res, err := Scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	f := findByPolicy(res.Findings, "Play Billing Library")
	if f == nil {
		t.Fatal("Play Billing 7 was not reported")
	}
	if !strings.Contains(f.Title, "7.1") {
		t.Errorf("title should carry the detected version, got %q", f.Title)
	}
}

func TestBillingVersionSupportedIsClean(t *testing.T) {
	root := writeProject(t, map[string]string{
		"app/build.gradle": `dependencies { implementation("com.android.billingclient:billing-ktx:8.0.0") }`,
	})
	res, err := Scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if f := findByPolicy(res.Findings, "Play Billing Library"); f != nil {
		t.Errorf("Billing 8 is supported, got %q", f.Title)
	}
}

func TestAccountDeletionFiresOnAuthSDK(t *testing.T) {
	root := writeProject(t, map[string]string{
		"app/build.gradle": `android { defaultConfig { targetSdk = 36 } }
dependencies { implementation 'com.google.firebase:firebase-auth:23.0.0' }`,
	})
	res, err := Scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if findByPolicy(res.Findings, "Account deletion") == nil {
		t.Error("an auth SDK should raise the account deletion requirement")
	}
}

// A Gradle project with no Android manifest and no Android plugin is a JVM
// project, and must not collect Play findings.
func TestPureJVMGradleProjectIsNotScanned(t *testing.T) {
	root := writeProject(t, map[string]string{
		"build.gradle.kts": `plugins { kotlin("jvm") version "2.0.0" }
dependencies { implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.0") }`,
		"gradle/libs.versions.toml": "[versions]\nkotlin = \"2.0.0\"\n",
	})
	res, err := Scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("a pure JVM Gradle project produced %d Play findings: %+v", len(res.Findings), res.Findings)
	}
}

// Convention plugins are where many modern projects set targetSdk, and the
// library plugin's lint.targetSdk must never be read as the app's target.
func TestTargetSDKFromConventionPlugin(t *testing.T) {
	root := writeProject(t, map[string]string{
		"app/build.gradle.kts": `plugins { id("nowinandroid.android.application") }`,
		"build-logic/convention/src/main/kotlin/AndroidApplicationConventionPlugin.kt": `class AndroidApplicationConventionPlugin : Plugin<Project> {
    override fun apply(target: Project) {
        with(target) {
            defaultConfig.targetSdk = 36
        }
    }
}`,
		"build-logic/convention/src/main/kotlin/AndroidLibraryConventionPlugin.kt": `class AndroidLibraryConventionPlugin : Plugin<Project> {
    override fun apply(target: Project) {
        lint.targetSdk = 30
        testOptions.targetSdk = 30
    }
}`,
	})
	res, err := Scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if res.TargetSDK != 36 {
		t.Errorf("TargetSDK = %d, want 36 from the application convention plugin", res.TargetSDK)
	}
	if f := findByPolicy(res.Findings, "Target API level"); f != nil {
		t.Errorf("targetSdk 36 is compliant, got %q", f.Title)
	}
}

func TestTargetSDKFromVersionCatalog(t *testing.T) {
	root := writeProject(t, map[string]string{
		"app/build.gradle.kts": `android {
    defaultConfig {
        targetSdk = libs.versions.targetSdk.get().toInt()
    }
}`,
		"gradle/libs.versions.toml": `[versions]
targetSdk = "34"
minSdk = "24"
`,
	})
	res, err := Scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if res.TargetSDK != 34 {
		t.Errorf("TargetSDK = %d, want 34 resolved from the version catalog", res.TargetSDK)
	}
}

// lint.targetSdk must never be mistaken for the app's target, since reading a
// low lint target would report a compliant app as non-compliant.
func TestLintTargetSDKIsIgnored(t *testing.T) {
	root := writeProject(t, map[string]string{
		"app/build.gradle.kts": `android {
    lint.targetSdk = 30
    testOptions.targetSdk = 30
    defaultConfig {
        targetSdk = 36
    }
}`,
	})
	res, err := Scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if res.TargetSDK != 36 {
		t.Errorf("TargetSDK = %d, want 36; a lint/test target was read as the app's", res.TargetSDK)
	}
}

func TestCleanProjectProducesNoFindings(t *testing.T) {
	root := writeProject(t, map[string]string{
		"app/build.gradle": `android {
    defaultConfig {
        minSdk = 24
        targetSdk = 36
    }
}
dependencies {
    implementation 'androidx.core:core-ktx:1.13.0'
}`,
		"app/src/main/AndroidManifest.xml": manifestHeader + `
    <uses-permission android:name="android.permission.INTERNET" />
    <application android:label="App">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter><action android:name="android.intent.action.MAIN" /></intent-filter>
        </activity>
    </application>
</manifest>`,
	})
	res, err := Scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Findings) != 0 {
		for _, f := range res.Findings {
			t.Errorf("unexpected finding: [%s] %s", f.Severity, f.Title)
		}
	}
	if res.PackageName != "com.example.app" {
		t.Errorf("PackageName = %q", res.PackageName)
	}
}

func TestNonAndroidProjectScansClean(t *testing.T) {
	root := writeProject(t, map[string]string{
		"App.swift": "import SwiftUI",
		"app.json":  `{"expo":{"name":"x"}}`,
	})
	if Detect(root) {
		t.Error("an iOS-only project must not be detected as Android")
	}
	res, err := Scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Findings) != 0 || res.ManifestPath != "" {
		t.Errorf("expected an empty result, got %+v", res)
	}
}

func TestDetectFindsExpoAndroidDirectory(t *testing.T) {
	root := writeProject(t, map[string]string{
		"app.json":                 `{"expo":{"name":"x"}}`,
		"android/app/build.gradle": "android { defaultConfig { targetSdk = 36 } }",
	})
	if !Detect(root) {
		t.Error("an Expo project with a prebuilt android/ directory is an Android project")
	}
}

// Build outputs contain generated manifests that must never be scanned in
// place of the developer's own.
func TestDiscoverSkipsBuildOutput(t *testing.T) {
	root := writeProject(t, map[string]string{
		"app/src/main/AndroidManifest.xml": manifestHeader + `<application /></manifest>`,
		"app/build/intermediates/merged_manifests/release/AndroidManifest.xml": manifestHeader + `
    <uses-permission android:name="android.permission.READ_SMS" />
    <application /></manifest>`,
	})
	res, err := Scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if filepath.ToSlash(res.ManifestPath) != "app/src/main/AndroidManifest.xml" {
		t.Errorf("ManifestPath = %q, want the source manifest", res.ManifestPath)
	}
	if findByPolicy(res.Findings, "SMS and Call Log permissions") != nil {
		t.Error("a permission from a build-output manifest leaked into the scan")
	}
}

// In a multi-module repo the app module is often not named "app", so path
// shape alone picks the wrong manifest and silently hides the real app's
// permissions. The launcher activity is what identifies the shipped app.
func TestSelectsAppManifestInMultiModuleProject(t *testing.T) {
	root := writeProject(t, map[string]string{
		"app/build.gradle": "android { defaultConfig { targetSdk = 36 } }",
		// A benchmark module whose path scores well but ships nothing.
		"baselineprofile/src/main/AndroidManifest.xml": manifestHeader + `
    <application />
</manifest>`,
		// A library module, also no launcher.
		"common/src/main/AndroidManifest.xml": manifestHeader + `
    <application />
</manifest>`,
		// The real app, in a module named after the product.
		"MyProduct/src/main/AndroidManifest.xml": manifestHeader + `
    <uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE" />
    <application>
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>`,
	})
	res, err := Scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if filepath.ToSlash(res.ManifestPath) != "MyProduct/src/main/AndroidManifest.xml" {
		t.Fatalf("ManifestPath = %q, want the module with the launcher activity", res.ManifestPath)
	}
	if findByPolicy(res.Findings, "All files access") == nil {
		t.Error("the real app's restricted permission was missed")
	}
}

func TestMalformedManifestIsReportedNotSwallowed(t *testing.T) {
	root := writeProject(t, map[string]string{
		"app/src/main/AndroidManifest.xml": manifestHeader + `
    <application>
</manifest>`,
	})
	res, err := Scan(root)
	if err != nil {
		t.Fatalf("scan should not hard-fail on a bad manifest: %v", err)
	}
	f := findByPolicy(res.Findings, "Scan coverage")
	if f == nil {
		t.Fatal("a malformed manifest must surface as a finding, not a silent pass")
	}
}

// itoa avoids pulling strconv into the test file for one call.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// play-services-auth-blockstore is credential backup and
// play-services-auth-api-phone is SMS retrieval; neither means the app creates
// accounts. Matching them raised a HIGH on an app with no accounts at all.
func TestAuthSDKDetectionExcludesNonAuthArtifacts(t *testing.T) {
	notAuth := []string{
		`implementation "com.google.android.gms:play-services-auth-blockstore:_"`,
		`implementation "com.google.android.gms:play-services-auth-api-phone:18.0.1"`,
	}
	for _, dep := range notAuth {
		root := writeProject(t, map[string]string{
			"app/build.gradle": "android { defaultConfig { targetSdk = 36 } }\ndependencies {\n    " + dep + "\n}",
		})
		res, err := Scan(root)
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if f := findByPolicy(res.Findings, "Account deletion"); f != nil {
			t.Errorf("%s is not an auth SDK but raised the account deletion rule", dep)
		}
	}

	isAuth := []string{
		`implementation "com.google.android.gms:play-services-auth:21.6.0"`,
		`implementation "com.google.firebase:firebase-auth-ktx:23.0.0"`,
	}
	for _, dep := range isAuth {
		root := writeProject(t, map[string]string{
			"app/build.gradle": "android { defaultConfig { targetSdk = 36 } }\ndependencies {\n    " + dep + "\n}",
		})
		res, err := Scan(root)
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if findByPolicy(res.Findings, "Account deletion") == nil {
			t.Errorf("%s is an auth SDK and should raise the account deletion rule", dep)
		}
	}
}

// Real projects reach targetSdk through a named constant far more often than
// they inline it. Each shape here came from a shipping open-source app.
func TestTargetSDKResolvedThroughReferences(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  int
	}{
		{
			name: "gradle ext variable (DuckDuckGo)",
			files: map[string]string{
				"build.gradle":     "ext {\n    target_sdk = 35\n}",
				"app/build.gradle": "android {\n    defaultConfig {\n        targetSdk target_sdk\n    }\n}",
			},
			want: 35,
		},
		{
			name: "kotlin object constant (Thunderbird)",
			files: map[string]string{
				"build-plugin/src/main/kotlin/ProjectConfig.kt":       "object ProjectConfig {\n    object Android {\n        const val sdkTarget = 35\n    }\n}",
				"build-plugin/src/main/kotlin/app.android.gradle.kts": "android {\n    defaultConfig {\n        targetSdk = ProjectConfig.Android.sdkTarget\n    }\n}",
			},
			want: 35,
		},
		{
			name: "extra property set() (Pocket Casts)",
			files: map[string]string{
				"dependencies.gradle.kts": `extra.apply {
    set("targetSdkVersion", 36)
    set("targetSdkVersionWear", 34)
}`,
				"app/build.gradle.kts": "android {\n    defaultConfig {\n        targetSdk = project.property(\"targetSdkVersion\") as Int\n    }\n}",
			},
			want: 36,
		},
		{
			name: "gradle.properties",
			files: map[string]string{
				"gradle.properties": "android.useAndroidX=true\nTARGET_SDK=33\n",
				"app/build.gradle":  "android {\n    defaultConfig {\n        targetSdk TARGET_SDK\n    }\n}",
			},
			want: 33,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := writeProject(t, tc.files)
			res, err := Scan(root)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if res.TargetSDK != tc.want {
				t.Errorf("TargetSDK = %d, want %d", res.TargetSDK, tc.want)
			}
		})
	}
}

// Most real builds reach the Billing Library version through a variable or a
// version catalog. Requiring a literal meant the support-window check silently
// never fired on them.
func TestBillingVersionResolvedThroughReferences(t *testing.T) {
	freezeClock(t, time.Date(2026, time.July, 27, 0, 0, 0, 0, time.UTC))
	cases := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{
			name: "groovy string interpolation",
			files: map[string]string{
				"app/build.gradle": `ext { billingVersion = "7.1.1" }
android { defaultConfig { targetSdk = 36 } }
dependencies { implementation "com.android.billingclient:billing:$billingVersion" }`,
			},
			want: "7.1",
		},
		{
			name: "version catalog version.ref",
			files: map[string]string{
				"app/build.gradle": `android { defaultConfig { targetSdk = 36 } }
dependencies { implementation libs.billing }`,
				"gradle/libs.versions.toml": `[versions]
billing = "6.2.0"

[libraries]
billing = { module = "com.android.billingclient:billing", version.ref = "billing" }`,
			},
			want: "6.2",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := writeProject(t, tc.files)
			res, err := Scan(root)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			f := findByPolicy(res.Findings, "Play Billing Library")
			if f == nil {
				t.Fatalf("an out-of-support billing version reached by reference was not detected")
			}
			if !strings.Contains(f.Title, tc.want) {
				t.Errorf("title = %q, want it to carry version %s", f.Title, tc.want)
			}
		})
	}
}

// A supported version reached by reference must stay clean.
func TestBillingVersionByReferenceSupportedIsClean(t *testing.T) {
	root := writeProject(t, map[string]string{
		"app/build.gradle": `ext { billingVersion = "8.0.0" }
android { defaultConfig { targetSdk = 36 } }
dependencies { implementation "com.android.billingclient:billing:$billingVersion" }`,
	})
	res, err := Scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if f := findByPolicy(res.Findings, "Play Billing Library"); f != nil {
		t.Errorf("Billing 8 is supported, got %q", f.Title)
	}
}
