package codescan

import (
	"regexp"
	"strings"
)

// Claims describes which flow-dependent features an app *claims* to implement,
// based on the same feature-detection patterns used by the static rules — but
// WITHOUT the anti-pattern suppression. A claim means "Apple will exercise this
// flow during review," which is exactly where static analysis goes blind: it can
// confirm a string like `deleteAccount` exists in source, never that the flow works.
type Claims struct {
	// Feature presence — the trigger patterns from the static rules.
	AccountCreation bool `json:"account_creation"`
	IAP             bool `json:"iap"`
	SocialLogin     bool `json:"social_login"`

	// Anti-pattern presence — the strings that cause the static scanner to
	// SUPPRESS the corresponding warning. When a feature is claimed AND its
	// anti-pattern code is present, static reports GREENLIT — and that is the
	// precise false-negative runtime validation exists to catch.
	HasDeleteAccountCode bool `json:"has_delete_account_code"`
	HasRestoreCode       bool `json:"has_restore_code"`
	HasSignInWithApple   bool `json:"has_sign_in_with_apple"`

	// Permission-gated API presence (camera/microphone/photo library/location)
	// and whether the matching Info.plist usage-description key is present —
	// mirrors the four permission-usage rules in rules_permissions.go. A
	// permission category is claimed independently of the others, and each
	// has its own key, so e.g. declaring NSCameraUsageDescription does not
	// satisfy a claimed microphone usage.
	CameraAPI       bool `json:"camera_api"`
	MicrophoneAPI   bool `json:"microphone_api"`
	PhotoLibraryAPI bool `json:"photo_library_api"`
	LocationAPI     bool `json:"location_api"`

	HasCameraUsageDescription       bool `json:"has_camera_usage_description"`
	HasMicrophoneUsageDescription   bool `json:"has_microphone_usage_description"`
	HasPhotoLibraryUsageDescription bool `json:"has_photo_library_usage_description"`
	HasLocationUsageDescription     bool `json:"has_location_usage_description"`
}

// These mirror the patterns/antiPatterns in rules.go for the three flow-dependent
// rules (account-no-delete, iap-no-restore, social-login-no-apple). Kept in sync
// deliberately: the runtime tier re-checks exactly the flows static can only guess.
var (
	reAccountCreation = regexp.MustCompile(`(?i)(createAccount|signUp|register.*user|create.*account|auth\(\)\.createUser)`)
	reIAP             = regexp.MustCompile(`(?i)(SKPaymentQueue|StoreKit|Product\.purchase|purchaseProduct|expo-in-app-purchases|react-native-iap|RevenueCat)`)
	reSocialLogin     = regexp.MustCompile(`(?i)(google.*sign.*in|GIDSignIn|GoogleSignin|facebook.*login|FBSDKLoginManager|LoginManager\.logIn)`)

	reDeleteAccount = regexp.MustCompile(`(?i)(deleteAccount|delete.*account|remove.*account|account.*delet|close.*account|closeAccount|cancel.*account|delete.*my.*account|erase.*account)`)
	reRestore       = regexp.MustCompile(`(?i)(restoreCompletedTransactions|restore.*purchase|restorePurchase|customerInfo|syncPurchases)`)
	reSiwA          = regexp.MustCompile(`(?i)(ASAuthorizationAppleIDProvider|SignInWithApple|apple.*auth|appleAuth|expo-apple-authentication)`)

	// Mirror the four permission-usage rules in rules_permissions.go.
	reCameraAPI       = regexp.MustCompile(`\bAVCaptureSession\s*\(|\bAVCaptureDevice\.(default|requestAccess|authorizationStatus)\b|(?i)(expo-camera|expo-barcode-scanner|react-native-vision-camera|react-native-camera)\b`)
	reMicrophoneAPI   = regexp.MustCompile(`\bAVAudioApplication\.requestRecordPermission\b|\.requestRecordPermission\s*\(|AVCaptureDevice\.requestAccess\(\s*for:\s*\.audio\s*\)|(?i)(expo-av\b|react-native-audio-recorder-player|@react-native-voice/voice|react-native-voice)\b`)
	rePhotoLibraryAPI = regexp.MustCompile(`\bPHPhotoLibrary\.(requestAuthorization|shared)\b|\bUIImagePickerController\s*\(|(?i)(expo-media-library|react-native-image-picker|react-native-cameraroll|@react-native-camera-roll/camera-roll)\b`)
	reLocationAPI     = regexp.MustCompile(`\.request(WhenInUseAuthorization|AlwaysAuthorization)\s*\(\s*\)|(?i)(expo-location\b|react-native-geolocation-service|@react-native-community/geolocation)\b`)

	reCameraUsageDescription       = regexp.MustCompile(`NSCameraUsageDescription`)
	reMicrophoneUsageDescription   = regexp.MustCompile(`NSMicrophoneUsageDescription`)
	rePhotoLibraryUsageDescription = regexp.MustCompile(`NSPhotoLibraryUsageDescription`)
	reLocationUsageDescription     = regexp.MustCompile(`NSLocation(WhenInUseUsageDescription|AlwaysAndWhenInUseUsageDescription|AlwaysUsageDescription)`)
)

// DetectClaims walks the project — reusing the scanner's file collection and
// language detection — and reports which flow-dependent features are present.
func DetectClaims(root string) (Claims, error) {
	s := &Scanner{root: root}
	files, err := s.collectFiles()
	if err != nil {
		return Claims{}, err
	}

	var c Claims
	for _, fc := range files {
		// The permission usage-description keys live in Info.plist, not
		// source — checked first, independently of the source-only switch
		// below, so a plist file isn't skipped before it gets a chance.
		if fc.Language == "plist" {
			content := strings.Join(fc.Lines, "\n")
			if reCameraUsageDescription.MatchString(content) {
				c.HasCameraUsageDescription = true
			}
			if reMicrophoneUsageDescription.MatchString(content) {
				c.HasMicrophoneUsageDescription = true
			}
			if rePhotoLibraryUsageDescription.MatchString(content) {
				c.HasPhotoLibraryUsageDescription = true
			}
			if reLocationUsageDescription.MatchString(content) {
				c.HasLocationUsageDescription = true
			}
			continue
		}

		switch fc.Language {
		case "swift", "objc", "typescript", "javascript":
		default:
			continue // ignore other json config — claims live in source
		}
		content := strings.Join(fc.Lines, "\n")
		if reAccountCreation.MatchString(content) {
			c.AccountCreation = true
		}
		if reIAP.MatchString(content) {
			c.IAP = true
		}
		if reSocialLogin.MatchString(content) {
			c.SocialLogin = true
		}
		if reDeleteAccount.MatchString(content) {
			c.HasDeleteAccountCode = true
		}
		if reRestore.MatchString(content) {
			c.HasRestoreCode = true
		}
		if reSiwA.MatchString(content) {
			c.HasSignInWithApple = true
		}
		if reCameraAPI.MatchString(content) {
			c.CameraAPI = true
		}
		if reMicrophoneAPI.MatchString(content) {
			c.MicrophoneAPI = true
		}
		if rePhotoLibraryAPI.MatchString(content) {
			c.PhotoLibraryAPI = true
		}
		if reLocationAPI.MatchString(content) {
			c.LocationAPI = true
		}
	}
	return c, nil
}
