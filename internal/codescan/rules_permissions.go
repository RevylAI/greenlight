package codescan

import "regexp"

// permissionUsageRules flags source code that triggers an iOS system
// permission prompt (camera, microphone, photo library, location) with no
// corresponding Info.plist purpose-string key declared anywhere in the
// project.
//
// This is a distinct gap from the two purpose-string checks that already
// exist:
//   - vague-purpose-string checks the WORDING of a key that already exists.
//   - missing-privacy-keys (PlistKeyRule) checks that a key which already
//     exists in Info.plist is not left EMPTY.
//
// Neither catches the far more common mistake: the key is never added at
// all. Xcode does not warn about this at build time — iOS terminates the
// app the instant the permission API is called at runtime ("This app has
// crashed because it attempted to access privacy-sensitive data without a
// usage description"). App Review hits that crash on its very first
// pass-through of the flow the key was supposed to cover, which is a §2.1
// crash rejection with a §5.1.1 purpose-string root cause — one of the most
// common real-world first-submission rejections, and one no code review
// catches because the broken state (key present vs. absent) is invisible
// unless you cross-reference it against actual API usage.
//
// Shaped like the project's other flow-dependent rules (account-no-delete,
// iap-no-restore, social-login-no-apple, missing-att): a `patterns` match
// (the permission-gated API or the library that wraps it) fires HIGH unless
// an `antiPatterns` match (the Info.plist key) is found anywhere in the
// project — matched project-wide via antiPatternsGlobal, since the key lives
// in Info.plist, a different file than the API call. "plist" is added to
// `languages` (alongside the source languages) purely so the anti-pattern
// first pass in scanner.go, which only inspects files a rule Applies() to,
// also walks Info.plist; the `patterns` themselves never match plist XML.
//
// Four categories are covered here (camera, microphone, photo library,
// location) — the ones that dominate real "missing usage description" crash
// reports. Each needs its own rule, not one merged rule, because each has
// its own Info.plist key: merging them into a single antiPatterns set would
// let an app that declares ONLY NSCameraUsageDescription incorrectly
// suppress a real missing NSMicrophoneUsageDescription finding.
func permissionUsageRules() []Rule {
	return []Rule{
		&PatternRule{
			id:        "camera-no-usage-description",
			title:     "Camera API used without NSCameraUsageDescription",
			guideline: "5.1.1",
			severity:  SeverityHigh,
			detail:    "AVCaptureSession/AVCaptureDevice (or a camera library built on them) is used, but no NSCameraUsageDescription key was found anywhere in the project. iOS kills the app the instant it requests camera access without that key — a crash, not a soft denial.",
			fix:       "Add NSCameraUsageDescription to Info.plist with a specific reason the app needs the camera, e.g. 'Scan receipts to log expenses'.",
			languages: []string{"swift", "objc", "typescript", "javascript", "plist"},
			patterns: []*regexp.Regexp{
				// AVCaptureDevice.default/.requestAccess/.authorizationStatus are
				// the real gating calls; a bare `AVCaptureSession()` is also
				// included since that's what most camera-preview code actually
				// instantiates. Class-qualified so a bare `.default` enum case
				// elsewhere can't match.
				regexp.MustCompile(`\bAVCaptureSession\s*\(|\bAVCaptureDevice\.(default|requestAccess|authorizationStatus)\b`),
				regexp.MustCompile(`(?i)(expo-camera|expo-barcode-scanner|react-native-vision-camera|react-native-camera)\b`),
			},
			antiPatterns: []*regexp.Regexp{
				regexp.MustCompile(`NSCameraUsageDescription`),
			},
			antiPatternsGlobal: true,
			firstMatchOnly:     true,
		},
		&PatternRule{
			id:        "microphone-no-usage-description",
			title:     "Microphone API used without NSMicrophoneUsageDescription",
			guideline: "5.1.1",
			severity:  SeverityHigh,
			detail:    "Audio recording (AVAudioSession/AVAudioApplication record permission, or a library built on it) is used, but no NSMicrophoneUsageDescription key was found anywhere in the project. iOS kills the app the instant it requests microphone access without that key.",
			fix:       "Add NSMicrophoneUsageDescription to Info.plist with a specific reason the app needs the microphone, e.g. 'Record voice notes for your journal entries'.",
			languages: []string{"swift", "objc", "typescript", "javascript", "plist"},
			patterns: []*regexp.Regexp{
				// AVAudioApplication.requestRecordPermission is the iOS 17+ API;
				// AVAudioSession's is the one it replaces. AVCaptureDevice's
				// .audio media type covers AVCaptureSession-based audio capture
				// (distinct call shape from the camera rule's .video checks).
				regexp.MustCompile(`\bAVAudioApplication\.requestRecordPermission\b|\.requestRecordPermission\s*\(|AVCaptureDevice\.requestAccess\(\s*for:\s*\.audio\s*\)`),
				regexp.MustCompile(`(?i)(expo-av\b|react-native-audio-recorder-player|@react-native-voice/voice|react-native-voice)\b`),
			},
			antiPatterns: []*regexp.Regexp{
				regexp.MustCompile(`NSMicrophoneUsageDescription`),
			},
			antiPatternsGlobal: true,
			firstMatchOnly:     true,
		},
		&PatternRule{
			id:        "photo-library-no-usage-description",
			title:     "Photo library API used without NSPhotoLibraryUsageDescription",
			guideline: "5.1.1",
			severity:  SeverityHigh,
			detail:    "PHPhotoLibrary or UIImagePickerController (or a library built on them) is used, but no NSPhotoLibraryUsageDescription key was found anywhere in the project. iOS kills the app the instant it requests photo library access without that key.",
			fix:       "Add NSPhotoLibraryUsageDescription to Info.plist with a specific reason the app needs photo library access, e.g. 'Attach photos from your library to a support ticket'.",
			languages: []string{"swift", "objc", "typescript", "javascript", "plist"},
			patterns: []*regexp.Regexp{
				// Deliberately PHPhotoLibrary/UIImagePickerController, not the
				// newer PHPickerViewController — PHPicker runs out-of-process and
				// Apple explicitly documents it as NOT requiring this key, so
				// including it would false-positive on every modern picker-only
				// app.
				regexp.MustCompile(`\bPHPhotoLibrary\.(requestAuthorization|shared)\b|\bUIImagePickerController\s*\(`),
				regexp.MustCompile(`(?i)(expo-media-library|react-native-image-picker|react-native-cameraroll|@react-native-camera-roll/camera-roll)\b`),
			},
			antiPatterns: []*regexp.Regexp{
				regexp.MustCompile(`NSPhotoLibraryUsageDescription`),
			},
			antiPatternsGlobal: true,
			firstMatchOnly:     true,
		},
		&PatternRule{
			id:        "location-no-usage-description",
			title:     "Location API used without a location usage description",
			guideline: "5.1.1",
			severity:  SeverityHigh,
			detail:    "CLLocationManager's When In Use or Always authorization request (or a library built on it) is used, but no NSLocationWhenInUseUsageDescription / NSLocationAlwaysAndWhenInUseUsageDescription key was found anywhere in the project. iOS kills the app the instant it requests location access without the matching key.",
			fix:       "Add NSLocationWhenInUseUsageDescription (and NSLocationAlwaysAndWhenInUseUsageDescription if the app also requests Always access) to Info.plist with a specific reason, e.g. 'Show nearby stores on the map'.",
			languages: []string{"swift", "objc", "typescript", "javascript", "plist"},
			patterns: []*regexp.Regexp{
				regexp.MustCompile(`\.request(WhenInUseAuthorization|AlwaysAuthorization)\s*\(\s*\)`),
				regexp.MustCompile(`(?i)(expo-location\b|react-native-geolocation-service|@react-native-community/geolocation)\b`),
			},
			antiPatterns: []*regexp.Regexp{
				// Either key — When In Use or (the legacy or current) Always
				// form — is accepted. Precisely which one the app needs depends
				// on which authorization call it made, which the project's own
				// existing missing-privacy-keys/vague-purpose-string checks
				// already cover at the wording level; this rule's job is only
				// "is there a location key at all."
				regexp.MustCompile(`NSLocation(WhenInUseUsageDescription|AlwaysAndWhenInUseUsageDescription|AlwaysUsageDescription)`),
			},
			antiPatternsGlobal: true,
			firstMatchOnly:     true,
		},
	}
}
