package checks

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/RevylAI/greenlight/internal/asc"
)

// checkAppExists verifies the app is accessible via the API.
func checkAppExists(ctx context.Context, client *asc.Client, appID string, findings *[]Finding) error {
	app, err := client.GetApp(appID)
	if err != nil {
		*findings = append(*findings, Finding{
			Tier:     TierMetadata,
			Severity: SeverityBlock,
			Title:    "App not found",
			Detail:   fmt.Sprintf("Could not access app %s. Verify the app ID and API key permissions.", appID),
			Fix:      "Check that your API key has App Manager access and the app ID is correct.",
		})
		return nil
	}

	if app.Attributes.Name == "" {
		*findings = append(*findings, Finding{
			Tier:      TierMetadata,
			Severity:  SeverityBlock,
			Guideline: "2.3",
			Title:     "App name is empty",
			Detail:    "The app has no name set in App Store Connect.",
			Fix:       "Set the app name in App Store Connect → App Information.",
		})
	}

	return nil
}

// checkVersionPrepared verifies a version exists in a submittable state.
func checkVersionPrepared(ctx context.Context, client *asc.Client, appID string, findings *[]Finding) error {
	versions, err := client.GetAppStoreVersions(appID)
	if err != nil {
		return err
	}

	if len(versions) == 0 {
		*findings = append(*findings, Finding{
			Tier:     TierMetadata,
			Severity: SeverityBlock,
			Title:    "No version found",
			Detail:   "No App Store version in a submittable state.",
			Fix:      "Create a new version in App Store Connect.",
		})
		return nil
	}

	latest := versions[0]
	state := latest.Attributes.AppStoreState
	if state != "PREPARE_FOR_SUBMISSION" && state != "DEVELOPER_REJECTED" {
		*findings = append(*findings, Finding{
			Tier:     TierMetadata,
			Severity: SeverityInfo,
			Title:    fmt.Sprintf("Version %s is in state: %s", latest.Attributes.VersionString, state),
			Detail:   "Version may not be editable in its current state.",
		})
	}

	return nil
}

// App Store Connect metadata limits.
const (
	maxDescriptionLength     = 4000
	maxKeywordsLength        = 100
	maxWhatsNewLength        = 4000
	maxPromotionalTextLength = 170
	maxAppNameLength         = 30
	maxSubtitleLength        = 30
)

// checkMetadataCompleteness verifies all required metadata fields and their length limits.
func checkMetadataCompleteness(ctx context.Context, client *asc.Client, appID string, findings *[]Finding) error {
	versions, err := client.GetAppStoreVersions(appID)
	if err != nil || len(versions) == 0 {
		return err
	}

	localizations, err := client.GetVersionLocalizations(versions[0].ID)
	if err != nil {
		return err
	}

	if len(localizations) == 0 {
		*findings = append(*findings, Finding{
			Tier:      TierMetadata,
			Severity:  SeverityBlock,
			Guideline: "2.3",
			Title:     "No localizations found",
			Detail:    "Your app version has no localized metadata.",
			Fix:       "Add at least one localization with description, keywords, and screenshots.",
		})
		return nil
	}

	for _, loc := range localizations {
		attrs := loc.Attributes
		locale := attrs.Locale

		// Description: required + length limit
		desc := strings.TrimSpace(attrs.Description)
		if desc == "" {
			*findings = append(*findings, Finding{
				Tier:      TierMetadata,
				Severity:  SeverityBlock,
				Guideline: "2.3",
				Title:     fmt.Sprintf("[%s] Description is empty", locale),
				Detail:    "A description is required for App Store submission.",
				Fix:       "Add a description in App Store Connect → Version Information.",
			})
		} else if utf8.RuneCountInString(desc) > maxDescriptionLength {
			*findings = append(*findings, Finding{
				Tier:      TierMetadata,
				Severity:  SeverityBlock,
				Guideline: "2.3",
				Title:     fmt.Sprintf("[%s] Description exceeds %d character limit (%d chars)", locale, maxDescriptionLength, utf8.RuneCountInString(desc)),
				Detail:    "App Store Connect enforces a maximum description length.",
				Fix:       fmt.Sprintf("Shorten your description to %d characters or less.", maxDescriptionLength),
			})
		}

		// Keywords: recommended + length limit (100 chars including commas)
		kw := strings.TrimSpace(attrs.Keywords)
		if kw == "" {
			*findings = append(*findings, Finding{
				Tier:      TierMetadata,
				Severity:  SeverityWarn,
				Guideline: "2.3",
				Title:     fmt.Sprintf("[%s] Keywords are empty", locale),
				Detail:    "Keywords help users discover your app and are recommended.",
				Fix:       "Add relevant keywords separated by commas.",
			})
		} else if utf8.RuneCountInString(kw) > maxKeywordsLength {
			*findings = append(*findings, Finding{
				Tier:      TierMetadata,
				Severity:  SeverityBlock,
				Guideline: "2.3",
				Title:     fmt.Sprintf("[%s] Keywords exceed %d character limit (%d chars)", locale, maxKeywordsLength, utf8.RuneCountInString(kw)),
				Detail:    "Keywords field has a strict 100-character limit including commas and spaces.",
				Fix:       "Shorten your keywords to 100 characters. Remove less important terms or use shorter synonyms.",
			})
		}

		// What's New
		if strings.TrimSpace(attrs.WhatsNew) == "" {
			*findings = append(*findings, Finding{
				Tier:      TierMetadata,
				Severity:  SeverityWarn,
				Guideline: "2.3",
				Title:     fmt.Sprintf("[%s] 'What's New' text is empty", locale),
				Detail:    "Users expect release notes describing changes in each update.",
				Fix:       "Add release notes describing what changed in this version.",
			})
		}

		// Promotional text: length limit
		pt := strings.TrimSpace(attrs.PromotionalText)
		if pt != "" && utf8.RuneCountInString(pt) > maxPromotionalTextLength {
			*findings = append(*findings, Finding{
				Tier:      TierMetadata,
				Severity:  SeverityBlock,
				Guideline: "2.3",
				Title:     fmt.Sprintf("[%s] Promotional text exceeds %d character limit (%d chars)", locale, maxPromotionalTextLength, utf8.RuneCountInString(pt)),
				Detail:    "Promotional text has a 170-character limit.",
				Fix:       fmt.Sprintf("Shorten your promotional text to %d characters.", maxPromotionalTextLength),
			})
		}

		// Support URL: required
		if strings.TrimSpace(attrs.SupportURL) == "" {
			*findings = append(*findings, Finding{
				Tier:      TierMetadata,
				Severity:  SeverityBlock,
				Guideline: "1.5",
				Title:     fmt.Sprintf("[%s] Support URL is missing", locale),
				Detail:    "A support URL is required for App Store submission.",
				Fix:       "Add a support URL pointing to your help/contact page.",
			})
		}
	}

	return nil
}

// checkScreenshots verifies screenshot sets exist.
func checkScreenshots(ctx context.Context, client *asc.Client, appID string, findings *[]Finding) error {
	versions, err := client.GetAppStoreVersions(appID)
	if err != nil || len(versions) == 0 {
		return err
	}

	localizations, err := client.GetVersionLocalizations(versions[0].ID)
	if err != nil || len(localizations) == 0 {
		return err
	}

	// Check screenshots for the primary localization
	primaryLoc := localizations[0]
	sets, err := client.GetScreenshotSets(primaryLoc.ID)
	if err != nil {
		return err
	}

	if len(sets) == 0 {
		*findings = append(*findings, Finding{
			Tier:      TierMetadata,
			Severity:  SeverityBlock,
			Guideline: "2.3",
			Title:     "No screenshots uploaded",
			Detail:    "At least one set of screenshots is required for submission.",
			Fix:       "Upload screenshots for at least iPhone 6.7\" and 5.5\" display sizes.",
		})
		return nil
	}

	// Check for required device types
	requiredTypes := map[string]string{
		"APP_IPHONE_67": "iPhone 6.7\" (iPhone 15 Pro Max, 16 Pro Max)",
		"APP_IPHONE_55": "iPhone 5.5\" (iPhone 8 Plus)",
	}

	foundTypes := make(map[string]bool)
	for _, set := range sets {
		foundTypes[set.Attributes.ScreenshotDisplayType] = true
	}

	for typeKey, typeName := range requiredTypes {
		if !foundTypes[typeKey] {
			*findings = append(*findings, Finding{
				Tier:      TierMetadata,
				Severity:  SeverityWarn,
				Guideline: "2.3",
				Title:     fmt.Sprintf("Missing screenshots for %s", typeName),
				Detail:    "Screenshots for this device size may be required depending on your app's supported devices.",
				Fix:       fmt.Sprintf("Upload screenshots for %s display type.", typeName),
			})
		}
	}

	return nil
}

// checkBuildProcessed verifies a build is processed and ready.
func checkBuildProcessed(ctx context.Context, client *asc.Client, appID string, findings *[]Finding) error {
	builds, err := client.GetBuilds(appID)
	if err != nil {
		return err
	}

	if len(builds) == 0 {
		*findings = append(*findings, Finding{
			Tier:     TierMetadata,
			Severity: SeverityBlock,
			Title:    "No builds found",
			Detail:   "No builds have been uploaded to App Store Connect.",
			Fix:      "Upload a build using Xcode, xcodebuild, or 'asc publish appstore'.",
		})
		return nil
	}

	latest := builds[0]
	if latest.Attributes.ProcessingState != "VALID" {
		*findings = append(*findings, Finding{
			Tier:     TierMetadata,
			Severity: SeverityBlock,
			Title:    fmt.Sprintf("Build %s is in state: %s", latest.Attributes.Version, latest.Attributes.ProcessingState),
			Detail:   "The build must be in VALID state before submission.",
			Fix:      "Wait for build processing to complete, or upload a new build if processing failed.",
		})
	}

	return nil
}

// checkAgeRating verifies age rating has been declared.
func checkAgeRating(ctx context.Context, client *asc.Client, appID string, findings *[]Finding) error {
	infos, err := client.GetAppInfos(appID)
	if err != nil {
		return err
	}

	if len(infos) == 0 {
		*findings = append(*findings, Finding{
			Tier:      TierMetadata,
			Severity:  SeverityWarn,
			Guideline: "1.3",
			Title:     "Cannot verify age rating",
			Detail:    "Could not fetch app info to verify age rating declaration.",
		})
		return nil
	}

	info := infos[0]
	if info.Attributes.AppStoreAgeRating == "" {
		*findings = append(*findings, Finding{
			Tier:      TierMetadata,
			Severity:  SeverityBlock,
			Guideline: "1.3",
			Title:     "Age rating not declared",
			Detail:    "An age rating questionnaire must be completed before submission.",
			Fix:       "Complete the age rating questionnaire in App Store Connect → App Information.",
		})
	}

	return nil
}

// checkEncryption verifies encryption compliance status.
func checkEncryption(ctx context.Context, client *asc.Client, appID string, findings *[]Finding) error {
	builds, err := client.GetBuilds(appID)
	if err != nil || len(builds) == 0 {
		return err
	}

	latest := builds[0]
	if latest.Attributes.UsesNonExemptEncryption == nil {
		*findings = append(*findings, Finding{
			Tier:      TierMetadata,
			Severity:  SeverityWarn,
			Guideline: "5.0",
			Title:     "Encryption compliance not declared",
			Detail:    "You haven't declared whether your app uses non-exempt encryption.",
			Fix:       "Set ITSAppUsesNonExemptEncryption in Info.plist or declare in App Store Connect.",
		})
	}

	return nil
}

// Required screenshot dimensions for each display type.
var requiredScreenshotDimensions = map[string]struct {
	name   string
	width  int
	height int
}{
	"APP_IPHONE_67":         {"iPhone 6.7\"", 1290, 2796},
	"APP_IPHONE_65":         {"iPhone 6.5\"", 1284, 2778},
	"APP_IPHONE_55":         {"iPhone 5.5\"", 1242, 2208},
	"APP_IPAD_PRO_3GEN_129": {"iPad Pro 12.9\"", 2048, 2732},
	"APP_IPAD_PRO_129":      {"iPad Pro 12.9\" (2nd gen)", 2048, 2732},
}

// checkScreenshotDimensions validates that uploaded screenshots have correct dimensions.
func checkScreenshotDimensions(ctx context.Context, client *asc.Client, appID string, findings *[]Finding) error {
	versions, err := client.GetAppStoreVersions(appID)
	if err != nil || len(versions) == 0 {
		return err
	}

	localizations, err := client.GetVersionLocalizations(versions[0].ID)
	if err != nil || len(localizations) == 0 {
		return err
	}

	primaryLoc := localizations[0]
	sets, err := client.GetScreenshotSets(primaryLoc.ID)
	if err != nil || len(sets) == 0 {
		return nil // other checks handle missing screenshots
	}

	for _, set := range sets {
		displayType := set.Attributes.ScreenshotDisplayType
		expectedDims, ok := requiredScreenshotDimensions[displayType]
		if !ok {
			continue
		}

		screenshots, err := client.GetScreenshots(set.ID)
		if err != nil {
			continue
		}

		for _, ss := range screenshots {
			if ss.Attributes.ImageAsset == nil {
				continue
			}
			w := ss.Attributes.ImageAsset.Width
			h := ss.Attributes.ImageAsset.Height

			// Check both portrait and landscape orientations
			validPortrait := w == expectedDims.width && h == expectedDims.height
			validLandscape := w == expectedDims.height && h == expectedDims.width
			if !validPortrait && !validLandscape {
				*findings = append(*findings, Finding{
					Tier:      TierMetadata,
					Severity:  SeverityBlock,
					Guideline: "2.3",
					Title:     fmt.Sprintf("Screenshot wrong dimensions for %s: %dx%d", expectedDims.name, w, h),
					Detail:    fmt.Sprintf("Expected %dx%d (portrait) or %dx%d (landscape) for %s.", expectedDims.width, expectedDims.height, expectedDims.height, expectedDims.width, expectedDims.name),
					Fix:       fmt.Sprintf("Re-capture screenshots at the correct resolution for %s.", expectedDims.name),
				})
				break // one finding per set is enough
			}
		}
	}

	return nil
}

// checkTestFlightExternal checks if external TestFlight testing is configured.
func checkTestFlightExternal(ctx context.Context, client *asc.Client, appID string, findings *[]Finding) error {
	groups, err := client.GetBetaGroups(appID)
	if err != nil {
		// Non-fatal — API may not have access
		return nil
	}

	hasExternal := false
	for _, g := range groups {
		if !g.Attributes.IsInternalGroup {
			hasExternal = true
			break
		}
	}

	if !hasExternal {
		*findings = append(*findings, Finding{
			Tier:      TierMetadata,
			Severity:  SeverityInfo,
			Guideline: "2.2",
			Title:     "No external TestFlight group configured",
			Detail:    "External beta testing helps catch issues before App Review. No external beta groups were found.",
			Fix:       "Create an external TestFlight group in App Store Connect → TestFlight to get real user feedback before submission.",
		})
	}

	return nil
}

// checkTerritoryAvailability verifies the app is available in territories.
func checkTerritoryAvailability(ctx context.Context, client *asc.Client, appID string, findings *[]Finding) error {
	territories, err := client.GetAppAvailability(appID)
	if err != nil {
		return nil // non-fatal
	}

	if len(territories) == 0 {
		*findings = append(*findings, Finding{
			Tier:     TierMetadata,
			Severity: SeverityBlock,
			Title:    "App not available in any territory",
			Detail:   "The app has no territory availability configured.",
			Fix:      "Set territory availability in App Store Connect → Pricing and Availability.",
		})
	} else if len(territories) < 5 {
		*findings = append(*findings, Finding{
			Tier:     TierMetadata,
			Severity: SeverityInfo,
			Title:    fmt.Sprintf("App available in only %d territories", len(territories)),
			Detail:   "Your app is available in very few territories. Consider expanding for wider reach.",
			Fix:      "Review territory availability in App Store Connect → Pricing and Availability.",
		})
	}

	return nil
}

// checkPricingConsistency verifies pricing is set up.
func checkPricingConsistency(ctx context.Context, client *asc.Client, appID string, findings *[]Finding) error {
	prices, err := client.GetAppPriceSchedule(appID)
	if err != nil {
		// The price schedule endpoint can fail if no pricing is configured
		// This isn't necessarily an error for free apps
		return nil
	}

	if len(prices) == 0 {
		*findings = append(*findings, Finding{
			Tier:     TierMetadata,
			Severity: SeverityWarn,
			Title:    "No price schedule configured",
			Detail:   "No pricing information found. Ensure your app's price (including Free) is explicitly set.",
			Fix:      "Set pricing in App Store Connect → Pricing and Availability.",
		})
	}

	return nil
}

// checkAppNameLength validates the app name length against App Store limits.
func checkAppNameLength(ctx context.Context, client *asc.Client, appID string, findings *[]Finding) error {
	app, err := client.GetApp(appID)
	if err != nil {
		return nil
	}

	name := strings.TrimSpace(app.Attributes.Name)
	if utf8.RuneCountInString(name) > maxAppNameLength {
		*findings = append(*findings, Finding{
			Tier:      TierMetadata,
			Severity:  SeverityBlock,
			Guideline: "2.3",
			Title:     fmt.Sprintf("App name exceeds %d character limit (%d chars)", maxAppNameLength, utf8.RuneCountInString(name)),
			Detail:    "App Store app names are limited to 30 characters.",
			Fix:       fmt.Sprintf("Shorten your app name to %d characters or less.", maxAppNameLength),
		})
	}

	return nil
}

// checkURLReachability verifies that support/marketing URLs are reachable.
func checkURLReachability(ctx context.Context, client *asc.Client, appID string, findings *[]Finding) error {
	versions, err := client.GetAppStoreVersions(appID)
	if err != nil || len(versions) == 0 {
		return err
	}

	localizations, err := client.GetVersionLocalizations(versions[0].ID)
	if err != nil || len(localizations) == 0 {
		return err
	}

	httpClient := &http.Client{Timeout: 10 * time.Second}

	for _, loc := range localizations {
		urls := map[string]string{
			"Support URL":   loc.Attributes.SupportURL,
			"Marketing URL": loc.Attributes.MarketingURL,
		}

		for name, url := range urls {
			if url == "" {
				continue
			}
			resp, err := httpClient.Get(url)
			if err != nil || resp.StatusCode >= 400 {
				*findings = append(*findings, Finding{
					Tier:      TierContent,
					Severity:  SeverityWarn,
					Guideline: "2.3",
					Title:     fmt.Sprintf("[%s] %s is unreachable: %s", loc.Attributes.Locale, name, url),
					Detail:    "Apple verifies that URLs in your metadata are accessible during review.",
					Fix:       "Ensure the URL is live and returns a 200 status code.",
				})
			}
			if resp != nil {
				resp.Body.Close()
			}
		}
	}

	return nil
}
