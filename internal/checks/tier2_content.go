package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/RevylAI/greenlight/internal/asc"
)

// Patterns that reference competing platforms — a common rejection trigger.
var platformPatterns = []struct {
	pattern string
	name    string
}{
	{"android", "Android"},
	{"google play", "Google Play"},
	{"play store", "Play Store"},
	{"samsung", "Samsung"},
	{"windows phone", "Windows Phone"},
	{"blackberry", "BlackBerry"},
	{"huawei", "Huawei"},
	{"amazon appstore", "Amazon Appstore"},
}

// Patterns that indicate placeholder/incomplete content.
var placeholderPatterns = []string{
	"lorem ipsum",
	"placeholder",
	"coming soon",
	"under construction",
	"todo",
	"tbd",
	"insert ",
	"[your ",
	"example.com",
	"test app",
	"my app",
	"sample app",
	"default description",
}

// checkPlatformReferences scans metadata for references to competing platforms.
func checkPlatformReferences(ctx context.Context, client *asc.Client, appID string, findings *[]Finding) error {
	versions, err := client.GetAppStoreVersions(appID)
	if err != nil || len(versions) == 0 {
		return err
	}

	localizations, err := client.GetVersionLocalizations(versions[0].ID)
	if err != nil {
		return err
	}

	for _, loc := range localizations {
		locale := loc.Attributes.Locale
		fields := map[string]string{
			"description":      loc.Attributes.Description,
			"keywords":         loc.Attributes.Keywords,
			"what's new":       loc.Attributes.WhatsNew,
			"promotional text": loc.Attributes.PromotionalText,
		}

		for fieldName, fieldValue := range fields {
			lower := strings.ToLower(fieldValue)
			for _, pp := range platformPatterns {
				if strings.Contains(lower, pp.pattern) {
					*findings = append(*findings, Finding{
						Tier:      TierContent,
						Severity:  SeverityBlock,
						Guideline: "2.3",
						Title:     fmt.Sprintf("[%s] %s mentions %s in %s", locale, pp.name, pp.name, fieldName),
						Detail:    "Referencing competing platforms in App Store metadata is a common rejection reason.",
						Fix:       fmt.Sprintf("Remove the reference to %s from the %s field.", pp.name, fieldName),
					})
				}
			}
		}
	}

	return nil
}

// checkPlaceholderContent scans metadata for placeholder text.
func checkPlaceholderContent(ctx context.Context, client *asc.Client, appID string, findings *[]Finding) error {
	versions, err := client.GetAppStoreVersions(appID)
	if err != nil || len(versions) == 0 {
		return err
	}

	localizations, err := client.GetVersionLocalizations(versions[0].ID)
	if err != nil {
		return err
	}

	for _, loc := range localizations {
		locale := loc.Attributes.Locale
		fields := map[string]string{
			"description":      loc.Attributes.Description,
			"keywords":         loc.Attributes.Keywords,
			"what's new":       loc.Attributes.WhatsNew,
			"promotional text": loc.Attributes.PromotionalText,
		}

		for fieldName, fieldValue := range fields {
			lower := strings.ToLower(fieldValue)
			for _, pattern := range placeholderPatterns {
				if strings.Contains(lower, pattern) {
					*findings = append(*findings, Finding{
						Tier:      TierContent,
						Severity:  SeverityBlock,
						Guideline: "2.1",
						Title:     fmt.Sprintf("[%s] Placeholder content detected in %s", locale, fieldName),
						Detail:    fmt.Sprintf("Found '%s' — Apple rejects apps with placeholder or incomplete content.", pattern),
						Fix:       fmt.Sprintf("Replace placeholder text in %s with final content.", fieldName),
					})
				}
			}
		}
	}

	return nil
}
