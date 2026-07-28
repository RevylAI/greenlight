package playscan

import (
	"fmt"
	"strings"
	"time"
)

// Policy documentation URLs. Only pages verified to exist are referenced —
// a link that 404s is worse than no link, since the whole point of citing is
// that the developer can go read the rule themselves.
const (
	docTargetAPI       = "https://support.google.com/googleplay/android-developer/answer/11926878"
	docBillingDeprecat = "https://developer.android.com/google/play/billing/deprecation-faq"
	docRestrictedPerms = "https://support.google.com/googleplay/android-developer/answer/14115180"
	docForegroundSvc   = "https://support.google.com/googleplay/android-developer/answer/13392821"
	docAccountDeletion = "https://support.google.com/googleplay/android-developer/answer/13327111"
	docAdvertisingID   = "https://support.google.com/googleplay/android-developer/answer/6048248"
	docAppContent      = "https://support.google.com/googleplay/android-developer/answer/9859455"
	docProgramPolicy   = "https://support.google.com/googleplay/android-developer/answer/16810878"
	docJul2026Policy   = "https://support.google.com/googleplay/android-developer/answer/17134731"
	docPageSizes       = "https://developer.android.com/guide/practices/page-sizes"
	doc64Bit           = "https://developer.android.com/google/play/requirements/64-bit"
)

// Google Play's published requirements, as of the 2026 cycle.
const (
	// requiredTargetSDKNew is what new apps and updates must target from
	// targetAPIDeadline onward (Android 16).
	requiredTargetSDKNew = 36
	// requiredTargetSDKExisting is the floor an already-published app must
	// meet to stay available to new users on newer devices (Android 15).
	// This one is already in force.
	requiredTargetSDKExisting = 35
	// minSupportedBillingMajor is the lowest Play Billing Library major
	// version still supported after billingDeadline.
	minSupportedBillingMajor = 8
)

var (
	targetAPIDeadline = time.Date(2026, time.August, 31, 0, 0, 0, 0, time.UTC)
	// Play Billing Library 7 loses support on the same date. There is no
	// v7-to-v9 upgrade path; v8 is a required stop.
	billingDeadline = targetAPIDeadline

	// now is a package variable so deadline wording is testable without
	// waiting for the calendar.
	now = time.Now
)

// ruleContext is the parsed project state every rule reads.
type ruleContext struct {
	manifest     *Manifest
	gradle       *GradleInfo
	targetSDK    int
	manifestFile string
}

func (c *ruleContext) hasPermission(name string) bool {
	return c.manifest != nil && c.manifest.HasPermission(name)
}

// formFactor reports the Play track this app ships on, defaulting to phone when
// there is no manifest to read.
func (c *ruleContext) formFactor() FormFactor {
	if c.manifest == nil {
		return FormFactorPhone
	}
	return c.manifest.FormFactor()
}

type rule func(*ruleContext) []Finding

func allRules() []rule {
	return []rule{
		ruleTargetAPILevel,
		rulePlayBillingVersion,
		ruleRestrictedPermissions,
		ruleForegroundServiceTypes,
		ruleDebuggable,
		ruleExportedComponents,
		ruleCleartextTraffic,
		ruleAdvertisingID,
		ruleAccountDeletion,
	}
}

// deadlinePhrase renders a deadline as urgency a developer can act on, and
// stays correct after the date passes.
func deadlinePhrase(deadline time.Time) string {
	days := int(deadline.Sub(now()).Hours() / 24)
	switch {
	case days < 0:
		return fmt.Sprintf("The %s deadline has passed", deadline.Format("January 2, 2006"))
	case days == 0:
		return fmt.Sprintf("The deadline is today (%s)", deadline.Format("January 2, 2006"))
	case days == 1:
		return fmt.Sprintf("The deadline is tomorrow (%s)", deadline.Format("January 2, 2006"))
	default:
		return fmt.Sprintf("%d days left until %s", days, deadline.Format("January 2, 2006"))
	}
}

// ruleTargetAPILevel checks the annual target API level requirement, which is
// the single most common cause of an app silently losing distribution.
func ruleTargetAPILevel(c *ruleContext) []Finding {
	file, line := c.gradle.TargetSDKFile, c.gradle.TargetSDKLine
	if file == "" {
		file = c.manifestFile
		line = 0
	}

	// Play publishes a separate target API schedule per form factor. Holding a
	// Wear, TV, Automotive, or XR app to the phone schedule produces a blocking
	// finding Play would not produce, so report it without gating the build.
	//
	// An unresolved targetSdk falls through to the shared "could not determine"
	// finding below, because not knowing the value is worth reporting on every
	// track.
	if ff := c.formFactor(); ff != FormFactorPhone && c.targetSDK != 0 {
		if c.targetSDK >= requiredTargetSDKNew {
			return nil
		}
		return []Finding{{
			Severity: sevWarn,
			Policy:   "Target API level",
			Title:    fmt.Sprintf("targetSdk %d is below the phone requirement, and this is a %s app", c.targetSDK, ff),
			Detail: fmt.Sprintf(
				"This manifest declares a %s app, which Play holds to its own target API schedule rather than the phone and tablet one. "+
					"targetSdk %d is below the API %d the phone track requires from August 31, 2026, but the deadline that applies here is the %s schedule.",
				ff, c.targetSDK, requiredTargetSDKNew, ff),
			Fix:  fmt.Sprintf("Check the target API level Play requires for %s and confirm this app meets it. If the app also ships to phones, raise targetSdk to %d.", ff, requiredTargetSDKNew),
			Doc:  docTargetAPI,
			File: file,
			Line: line,
		}}
	}

	if c.targetSDK == 0 {
		// Nothing to check against, but silence would be misleading: the value
		// exists somewhere the scan could not resolve (an ext property, a
		// version catalog, a convention plugin).
		return []Finding{{
			Severity: sevWarn,
			Policy:   "Target API level",
			Title:    "Could not determine targetSdk",
			Detail: "No integer targetSdk was found in the Gradle files or the manifest, so the target API level requirement could not be checked. " +
				"This usually means the value comes from an ext property, a version catalog, or a convention plugin.",
			Fix:  fmt.Sprintf("Confirm your app targets API %d or higher before submitting. %s.", requiredTargetSDKNew, deadlinePhrase(targetAPIDeadline)),
			Doc:  docTargetAPI,
			File: file,
		}}
	}

	switch {
	case c.targetSDK < requiredTargetSDKExisting:
		return []Finding{{
			Severity: sevCritical,
			Policy:   "Target API level",
			Title:    fmt.Sprintf("targetSdk %d is below the API %d floor for existing apps", c.targetSDK, requiredTargetSDKExisting),
			Detail: fmt.Sprintf(
				"Apps already on Google Play must target API %d or higher to stay available to new users on devices running a newer Android version than the app targets. "+
					"At targetSdk %d the app is not discoverable or installable for those users. New submissions and updates must target API %d. %s.",
				requiredTargetSDKExisting, c.targetSDK, requiredTargetSDKNew, deadlinePhrase(targetAPIDeadline)),
			Fix:  fmt.Sprintf("Set targetSdk = %d in your app module's android {} block and re-test on Android 16.", requiredTargetSDKNew),
			Doc:  docTargetAPI,
			File: file,
			Line: line,
		}}

	case c.targetSDK < requiredTargetSDKNew:
		return []Finding{{
			Severity: sevHigh,
			Policy:   "Target API level",
			Title:    fmt.Sprintf("targetSdk %d is below API %d, required for new submissions", c.targetSDK, requiredTargetSDKNew),
			Detail: fmt.Sprintf(
				"New apps and updates to existing apps must target Android %d (API %d) or higher to be published. %s. "+
					"An extension can be requested in Play Console, but it only defers the requirement to November 1, 2026.",
				requiredTargetSDKNew-20, requiredTargetSDKNew, deadlinePhrase(targetAPIDeadline)),
			Fix:  fmt.Sprintf("Set targetSdk = %d in your app module's android {} block and re-test behaviour changes for Android 16.", requiredTargetSDKNew),
			Doc:  docTargetAPI,
			File: file,
			Line: line,
		}}
	}
	return nil
}

// rulePlayBillingVersion checks the Play Billing Library support window.
func rulePlayBillingVersion(c *ruleContext) []Finding {
	if c.gradle.BillingVersion == 0 {
		return nil
	}
	if c.gradle.BillingVersion >= minSupportedBillingMajor {
		return nil
	}
	return []Finding{{
		Severity: sevHigh,
		Policy:   "Play Billing Library",
		Title:    fmt.Sprintf("Play Billing Library %s is past its support window", c.gradle.BillingVersionRaw),
		Detail: fmt.Sprintf(
			"Play Billing Library 7 and below lose support and updates using them can no longer be published. %s. "+
				"There is no direct 7-to-9 upgrade: the version 8 migration has to be done first.",
			deadlinePhrase(billingDeadline)),
		Fix:  fmt.Sprintf("Upgrade com.android.billingclient:billing to %d.x or higher.", minSupportedBillingMajor),
		Doc:  docBillingDeprecat,
		File: c.gradle.BillingFile,
		Line: c.gradle.BillingLine,
	}}
}

// restrictedPermission is a permission whose mere presence creates a Play
// obligation — a declaration form, an approved use case, or a demo video.
type restrictedPermission struct {
	names    []string
	severity string
	policy   string
	title    string
	detail   string
	fix      string
	doc      string
	// minTargetSDK gates policies that only bind above a target level; 0 means
	// the policy applies regardless.
	minTargetSDK int
	// componentBound marks a BIND_* permission that is never requested via
	// <uses-permission>. The framework requires it as the android:permission
	// attribute of the <service> or <receiver> being bound, so checking only
	// the uses-permission list would never fire.
	componentBound bool
}

var restrictedPermissions = []restrictedPermission{
	{
		names: []string{
			"android.permission.READ_SMS", "android.permission.SEND_SMS",
			"android.permission.RECEIVE_SMS", "android.permission.RECEIVE_MMS",
			"android.permission.RECEIVE_WAP_PUSH", "android.permission.WRITE_SMS",
		},
		severity: sevHigh,
		policy:   "SMS and Call Log permissions",
		title:    "Restricted SMS permission requires an approved use case",
		detail: "SMS permissions are restricted. The app must have a Play-approved core use case and a completed Permissions Declaration Form, " +
			"or the update is rejected. Most one-time-password flows do not qualify because the SMS Retriever API covers them without the permission.",
		fix: "Remove the permission and use the SMS Retriever API, or file the Permissions Declaration Form with your approved use case.",
		doc: docRestrictedPerms,
	},
	{
		names:    []string{"android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG", "android.permission.PROCESS_OUTGOING_CALLS"},
		severity: sevHigh,
		policy:   "SMS and Call Log permissions",
		title:    "Restricted Call Log permission requires an approved use case",
		detail: "Call Log permissions are restricted and need a Play-approved core use case plus a Permissions Declaration Form. " +
			"As of the July 15, 2026 policy update, account verification by phone call is no longer a permitted use of READ_CALL_LOG, with compliance required by August 14, 2026.",
		fix: "Drop the permission, or move verification to the Digital Credentials API or SMS Retriever API. Keep it only with an approved declaration.",
		doc: docJul2026Policy,
	},
	{
		names:    []string{"android.permission.MANAGE_EXTERNAL_STORAGE"},
		severity: sevHigh,
		policy:   "All files access",
		title:    "MANAGE_EXTERNAL_STORAGE (All files access) requires approval",
		detail: "All files access is a restricted permission granted only to apps whose core purpose requires broad file management, such as file managers and backup tools. " +
			"Requesting it without an approved declaration is a common rejection.",
		fix: "Use the Storage Access Framework, MediaStore, or scoped directories instead. If the app genuinely needs it, file the declaration.",
		doc: docRestrictedPerms,
	},
	{
		names:    []string{"android.permission.QUERY_ALL_PACKAGES"},
		severity: sevHigh,
		policy:   "Package visibility",
		title:    "QUERY_ALL_PACKAGES requires an approved use case",
		detail: "Broad package visibility is restricted to apps that must discover any installed app, such as launchers, antivirus, and accessibility tools. " +
			"Other apps are expected to declare the specific packages they interact with.",
		fix: "Replace with a <queries> element listing the packages or intents you actually need. Keep the permission only with an approved declaration.",
		doc: docRestrictedPerms,
	},
	{
		names:    []string{"android.permission.REQUEST_INSTALL_PACKAGES"},
		severity: sevHigh,
		policy:   "Device and Network Abuse",
		title:    "REQUEST_INSTALL_PACKAGES needs a permitted use case",
		detail: "Installing other packages is restricted to a narrow set of use cases such as app stores and enterprise device management. " +
			"It is also read as a signal of distributing code outside Play, which the Device and Network Abuse policy prohibits.",
		fix: "Remove the permission unless the app's core purpose is app distribution or file management with an approved declaration.",
		doc: docProgramPolicy,
	},
	{
		names:    []string{"android.permission.ACCESS_BACKGROUND_LOCATION"},
		severity: sevHigh,
		policy:   "Background location",
		title:    "Background location requires a declaration and a demo video",
		detail: "Background location access is reviewed individually. The app must show the feature delivers clear user benefit, get user-facing consent, " +
			"and submit a video demonstrating the in-app flow that uses it. Review of this permission routinely takes multiple rounds.",
		fix: "Confirm foreground location is genuinely insufficient. If it is not, remove the permission. Otherwise budget review time and prepare the demo video.",
		doc: docRestrictedPerms,
	},
	{
		names:        []string{"android.permission.READ_MEDIA_IMAGES", "android.permission.READ_MEDIA_VIDEO"},
		severity:     sevWarn,
		policy:       "Photo and Video Permissions",
		title:        "Broad photo/video permission needs justification over the Photo Picker",
		detail:       "Apps targeting API 33 and above may request READ_MEDIA_IMAGES or READ_MEDIA_VIDEO only when the system photo picker cannot support the app's core functionality. One-off uploads such as an avatar picker do not qualify.",
		fix:          "Switch to the Android Photo Picker, which needs no permission. Keep broad access only if the app's core purpose requires a persistent full-library view.",
		doc:          docRestrictedPerms,
		minTargetSDK: 33,
	},
	{
		names:    []string{"android.permission.BIND_ACCESSIBILITY_SERVICE"},
		severity: sevHigh,
		policy:   "Accessibility API",
		title:    "Accessibility Service use is tightly restricted",
		detail: "The Accessibility APIs may only be used to help users with disabilities, and the app must disclose the use in the store listing and in-app. " +
			"Using accessibility for automation, overlays, or ad interaction is one of the most common causes of app suspension rather than simple rejection.",
		fix:            "Confirm the service exists to support users with disabilities and disclose it prominently. Otherwise use a purpose-built API.",
		doc:            docProgramPolicy,
		componentBound: true,
	},
	{
		names:    []string{"android.permission.SYSTEM_ALERT_WINDOW"},
		severity: sevWarn,
		policy:   "Overlay permissions",
		title:    "SYSTEM_ALERT_WINDOW draws over other apps",
		detail:   "Overlay windows are scrutinised because they are used to obscure disclosures and interfere with other apps. Overlays that hide consent dialogs or system UI violate policy.",
		fix:      "Use in-app UI, notifications, or picture-in-picture where possible. If the overlay is core, ensure it never obscures a permission or consent prompt.",
		doc:      docProgramPolicy,
	},
	{
		names:          []string{"android.permission.BIND_DEVICE_ADMIN"},
		severity:       sevWarn,
		policy:         "Device admin",
		title:          "Device administrator API requires a permitted use case",
		detail:         "Device admin is limited to genuine device management use cases. Using it to make the app hard to uninstall is an abuse signal.",
		fix:            "Confirm the app is an enterprise or family management tool, and that admin rights can be revoked normally.",
		doc:            docProgramPolicy,
		componentBound: true,
	},
	{
		names:          []string{"android.permission.BIND_VPN_SERVICE"},
		severity:       sevWarn,
		policy:         "VPN Service",
		title:          "VPN service requires the VpnService declaration",
		detail:         "Only apps whose core functionality is a VPN may use VpnService, and the use must be declared in Play Console. Using it to monitor or redirect other apps' traffic for analytics or ad injection violates policy.",
		fix:            "Confirm a VPN is the app's core purpose and complete the VPN declaration in Play Console.",
		doc:            docProgramPolicy,
		componentBound: true,
	},
	{
		names:    []string{"android.permission.PACKAGE_USAGE_STATS"},
		severity: sevWarn,
		policy:   "User Data",
		title:    "Usage access reads other apps' activity",
		detail:   "App usage data is personal and sensitive under the User Data policy. It requires prominent in-app disclosure and consent before collection, in addition to the Data safety declaration.",
		fix:      "Add a prominent disclosure before requesting usage access and declare the collection in the Data safety form.",
		doc:      docProgramPolicy,
	},
	{
		names:    []string{"android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS"},
		severity: sevInfo,
		policy:   "Contact Permissions",
		title:    "Contacts access is narrowing under the 2026 Contact Permissions policy",
		detail:   "A Contact Permissions policy introduced in April 2026 restricts READ_CONTACTS for apps targeting API 37 and above to cases where the system Contact Picker is insufficient. Contacts also require prominent disclosure and a Data safety declaration today.",
		fix:      "Plan a move to the system Contact Picker before targeting API 37, and confirm contacts are declared in the Data safety form.",
		doc:      docRestrictedPerms,
	},
}

func ruleRestrictedPermissions(c *ruleContext) []Finding {
	if c.manifest == nil {
		return nil
	}
	var findings []Finding
	for _, rp := range restrictedPermissions {
		if rp.minTargetSDK > 0 && c.targetSDK > 0 && c.targetSDK < rp.minTargetSDK {
			continue
		}
		var hit []string
		for _, name := range rp.names {
			if c.manifest.HasPermission(name) {
				hit = append(hit, shortPermission(name))
				continue
			}
			// BIND_* permissions are enforced on the component, not requested
			// by the app, so they appear as a component's android:permission.
			if rp.componentBound && c.manifest.HasComponentPermission(name) {
				hit = append(hit, shortPermission(name))
			}
		}
		if len(hit) == 0 {
			continue
		}
		findings = append(findings, Finding{
			Severity: rp.severity,
			Policy:   rp.policy,
			Title:    rp.title,
			Detail:   fmt.Sprintf("Declared: %s. %s", strings.Join(hit, ", "), rp.detail),
			Fix:      rp.fix,
			Doc:      rp.doc,
			File:     c.manifestFile,
		})
	}
	return findings
}

// foregroundServicePermissions maps each foreground service type to the
// permission Android 14 requires alongside it. A type declared without its
// permission throws SecurityException at startForeground() on API 34+.
var foregroundServicePermissions = map[string]string{
	"camera":          "android.permission.FOREGROUND_SERVICE_CAMERA",
	"connectedDevice": "android.permission.FOREGROUND_SERVICE_CONNECTED_DEVICE",
	"dataSync":        "android.permission.FOREGROUND_SERVICE_DATA_SYNC",
	"health":          "android.permission.FOREGROUND_SERVICE_HEALTH",
	"location":        "android.permission.FOREGROUND_SERVICE_LOCATION",
	"mediaPlayback":   "android.permission.FOREGROUND_SERVICE_MEDIA_PLAYBACK",
	"mediaProjection": "android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION",
	"microphone":      "android.permission.FOREGROUND_SERVICE_MICROPHONE",
	"phoneCall":       "android.permission.FOREGROUND_SERVICE_PHONE_CALL",
	"remoteMessaging": "android.permission.FOREGROUND_SERVICE_REMOTE_MESSAGING",
	"shortService":    "",
	"specialUse":      "android.permission.FOREGROUND_SERVICE_SPECIAL_USE",
	"systemExempted":  "android.permission.FOREGROUND_SERVICE_SYSTEM_EXEMPTED",
	"mediaProcessing": "android.permission.FOREGROUND_SERVICE_MEDIA_PROCESSING",
	"fileManagement":  "android.permission.FOREGROUND_SERVICE_FILE_MANAGEMENT",
}

// ruleForegroundServiceTypes checks that every declared foreground service type
// has its matching permission, and flags specialUse, which needs a separate
// Play Console declaration.
func ruleForegroundServiceTypes(c *ruleContext) []Finding {
	if c.manifest == nil || c.manifest.Application == nil {
		return nil
	}
	var findings []Finding
	reported := make(map[string]bool)

	// Every foreground service needs the base FOREGROUND_SERVICE permission
	// from API 28, independent of its type. Without it startForeground()
	// throws just as surely as a missing type-specific permission, so checking
	// only the type-specific ones misses the case entirely.
	declaresForegroundService := false
	for _, svc := range c.manifest.Application.Services {
		if svc.ForegroundSvcType != "" {
			declaresForegroundService = true
			break
		}
	}
	if declaresForegroundService && !c.manifest.HasPermission("android.permission.FOREGROUND_SERVICE") {
		findings = append(findings, Finding{
			Severity: sevCritical,
			Policy:   "Foreground services",
			Title:    "Foreground service declared without the FOREGROUND_SERVICE permission",
			Detail: "The manifest declares a foreground service but does not request android.permission.FOREGROUND_SERVICE, which every foreground service has required since API 28. " +
				"startForeground() throws SecurityException, so the feature fails on every supported device.",
			Fix:  "Add <uses-permission android:name=\"android.permission.FOREGROUND_SERVICE\" /> to the manifest.",
			Doc:  docForegroundSvc,
			File: c.manifestFile,
		})
	}

	for _, svc := range c.manifest.Application.Services {
		if svc.ForegroundSvcType == "" {
			continue
		}
		// A service may declare multiple types, pipe-separated.
		for _, t := range strings.Split(svc.ForegroundSvcType, "|") {
			t = strings.TrimSpace(t)
			perm, known := foregroundServicePermissions[t]
			if !known || perm == "" || reported[t] {
				continue
			}
			if c.manifest.HasPermission(perm) {
				continue
			}
			reported[t] = true
			findings = append(findings, Finding{
				Severity: sevCritical,
				Policy:   "Foreground services",
				Title:    fmt.Sprintf("Foreground service type %q is missing its required permission", t),
				Detail: fmt.Sprintf(
					"Service %s declares foregroundServiceType=%q but the manifest does not request %s. "+
						"On Android 14 and above the app throws SecurityException the moment it calls startForeground(), so the feature crashes on every current device.",
					displayComponentName(svc.Name), t, perm),
				Fix:  fmt.Sprintf("Add <uses-permission android:name=\"%s\" /> to the manifest.", perm),
				Doc:  docForegroundSvc,
				File: c.manifestFile,
			})
		}

		if strings.Contains(svc.ForegroundSvcType, "specialUse") && !reported["specialUse-decl"] {
			reported["specialUse-decl"] = true
			findings = append(findings, Finding{
				Severity: sevHigh,
				Policy:   "Foreground services",
				Title:    "specialUse foreground service requires a Play Console declaration",
				Detail: "The specialUse foreground service type exists for cases none of the defined types cover, and Play requires a written justification in Console describing the use case. " +
					"Submitting without it is rejected.",
				Fix:  "Declare the specialUse justification in Play Console under App content, or move the service to a defined foreground service type.",
				Doc:  docForegroundSvc,
				File: c.manifestFile,
			})
		}
	}
	return findings
}

func ruleDebuggable(c *ruleContext) []Finding {
	if c.manifest == nil || c.manifest.Application == nil {
		return nil
	}
	if !attrIsTrue(c.manifest.Application.Debuggable) {
		return nil
	}
	return []Finding{{
		Severity: sevCritical,
		Policy:   "Malicious Behavior",
		Title:    "android:debuggable is set to true",
		Detail: "Google Play rejects uploads whose manifest is marked debuggable. It also exposes the app's internals to any process on the device, " +
			"which is a security finding in its own right.",
		Fix:  "Remove android:debuggable from the manifest and let the build type control it. Release builds must never set it.",
		Doc:  docProgramPolicy,
		File: c.manifestFile,
	}}
}

// ruleExportedComponents catches the API 31 android:exported requirement. This
// is a hard install failure, not merely a policy matter.
func ruleExportedComponents(c *ruleContext) []Finding {
	if c.manifest == nil || c.manifest.Application == nil {
		return nil
	}
	// The requirement binds when targeting API 31+. An unknown target is not
	// assumed to be affected.
	if c.targetSDK != 0 && c.targetSDK < 31 {
		return nil
	}

	var missing []string
	for _, comp := range c.manifest.Application.Components() {
		if comp.HasIntentFilter() && !attrIsSet(comp.Exported) {
			missing = append(missing, displayComponentName(comp.Name))
		}
	}
	if len(missing) == 0 {
		return nil
	}
	if len(missing) > 5 {
		missing = append(missing[:5], fmt.Sprintf("and %d more", len(missing)-5))
	}
	return []Finding{{
		Severity: sevCritical,
		Policy:   "Manifest requirements",
		Title:    "Component with an intent filter is missing android:exported",
		Detail: fmt.Sprintf(
			"Apps targeting API 31 and above must set android:exported explicitly on every activity, service, and receiver that declares an intent filter. "+
				"Without it the package fails to install. Missing on: %s.",
			strings.Join(missing, ", ")),
		Fix:  "Add android:exported=\"true\" or \"false\" to each component listed, choosing false unless another app genuinely needs to start it.",
		Doc:  docProgramPolicy,
		File: c.manifestFile,
	}}
}

func ruleCleartextTraffic(c *ruleContext) []Finding {
	if c.manifest == nil || c.manifest.Application == nil {
		return nil
	}
	if !attrIsTrue(c.manifest.Application.UsesCleartextTraffic) {
		return nil
	}
	return []Finding{{
		Severity: sevWarn,
		Policy:   "User Data",
		Title:    "android:usesCleartextTraffic is enabled",
		Detail: "The app opts in to unencrypted HTTP for all destinations. Play requires personal and sensitive user data to be transmitted securely, " +
			"and cleartext traffic is a standard finding in pre-launch security reports.",
		Fix:  "Remove the attribute and use HTTPS. If specific legacy hosts need cleartext, allow only those in a network security config.",
		Doc:  docProgramPolicy,
		File: c.manifestFile,
	}}
}

// ruleAdvertisingID checks the AD_ID permission that ads SDKs require from
// API 33. Without it the advertising ID silently returns zeros rather than
// failing loudly, so this usually ships unnoticed and quietly breaks
// attribution.
func ruleAdvertisingID(c *ruleContext) []Finding {
	if !c.gradle.HasAdsSDK {
		return nil
	}
	if c.targetSDK != 0 && c.targetSDK < 33 {
		return nil
	}
	if c.hasPermission("com.google.android.gms.permission.AD_ID") {
		return nil
	}
	return []Finding{{
		Severity: sevHigh,
		Policy:   "Advertising ID",
		Title:    "Ads SDK present without the AD_ID permission",
		Detail: "An advertising or monetization SDK is a dependency, but the manifest does not declare com.google.android.gms.permission.AD_ID. " +
			"Apps targeting API 33 and above must declare it to read the advertising ID; without it the ID comes back as all zeros and attribution and ad revenue degrade silently. " +
			"The app's use of the advertising ID must also be declared in the Play Console Advertising ID section.",
		Fix:  "Add <uses-permission android:name=\"com.google.android.gms.permission.AD_ID\" /> and confirm the Advertising ID declaration in Play Console.",
		Doc:  docAdvertisingID,
		File: c.gradle.AdsSDKFile,
		Line: c.gradle.AdsSDKLine,
	}}
}

// ruleAccountDeletion surfaces the account deletion requirement when the app
// ships an auth SDK. Play requires deletion to be reachable two ways, and the
// web URL half is the one teams forget because nothing in the app references it.
func ruleAccountDeletion(c *ruleContext) []Finding {
	if !c.gradle.HasAuthSDK {
		return nil
	}
	return []Finding{{
		Severity: sevHigh,
		Policy:   "Account deletion",
		Title:    "Account creation requires in-app AND web account deletion",
		Detail: "An authentication SDK is a dependency, so the app appears to let users create accounts. Play requires such apps to offer account deletion from inside the app " +
			"and through a web URL that works without reinstalling, with that URL entered in the Data safety form. Deactivating or freezing an account does not satisfy this, " +
			"and associated user data must actually be deleted.",
		Fix: "Ship an in-app deletion flow, publish a deletion web page, and enter its URL in the Data safety section of Play Console.",
		Doc: docAccountDeletion,
	}}
}

// shortPermission trims the well-known android.permission prefix so findings
// read cleanly, leaving custom and vendor permissions fully qualified.
func shortPermission(name string) string {
	return strings.TrimPrefix(name, "android.permission.")
}

// displayComponentName renders a manifest component name, which is commonly a
// relative ".MainActivity" form.
func displayComponentName(name string) string {
	if name == "" {
		return "(unnamed)"
	}
	return name
}

// DocAppContent is exported so callers can point users at the Play Console
// declarations that no static scan can verify.
const DocAppContent = docAppContent
