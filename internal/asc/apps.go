package asc

import "fmt"

// App represents an App Store Connect app.
type App struct {
	ID         string        `json:"id"`
	Attributes AppAttributes `json:"attributes"`
}

type AppAttributes struct {
	Name                     string `json:"name"`
	BundleID                 string `json:"bundleId"`
	SKU                      string `json:"sku"`
	PrimaryLocale            string `json:"primaryLocale"`
	ContentRightsDeclaration string `json:"contentRightsDeclaration"`
}

// AppInfo contains app information details.
type AppInfo struct {
	ID         string            `json:"id"`
	Attributes AppInfoAttributes `json:"attributes"`
}

type AppInfoAttributes struct {
	AppStoreState     string `json:"appStoreState"`
	AppStoreAgeRating string `json:"appStoreAgeRating"`
	BrazilAgeRating   string `json:"brazilAgeRating"`
	KidsAgeBand       string `json:"kidsAgeBand"`
}

// AppStoreVersion represents a version of an app.
type AppStoreVersion struct {
	ID         string                    `json:"id"`
	Attributes AppStoreVersionAttributes `json:"attributes"`
}

type AppStoreVersionAttributes struct {
	VersionString string `json:"versionString"`
	AppStoreState string `json:"appStoreState"`
	Platform      string `json:"platform"`
	ReleaseType   string `json:"releaseType"`
	CreatedDate   string `json:"createdDate"`
}

// VersionLocalization contains localized version info.
type VersionLocalization struct {
	ID         string                        `json:"id"`
	Attributes VersionLocalizationAttributes `json:"attributes"`
}

type VersionLocalizationAttributes struct {
	Locale          string `json:"locale"`
	Description     string `json:"description"`
	Keywords        string `json:"keywords"`
	WhatsNew        string `json:"whatsNew"`
	SupportURL      string `json:"supportUrl"`
	MarketingURL    string `json:"marketingUrl"`
	PromotionalText string `json:"promotionalText"`
}

// Build represents a build uploaded to App Store Connect.
type Build struct {
	ID         string          `json:"id"`
	Attributes BuildAttributes `json:"attributes"`
}

type BuildAttributes struct {
	Version                 string `json:"version"`
	UploadedDate            string `json:"uploadedDate"`
	ProcessingState         string `json:"processingState"`
	MinOsVersion            string `json:"minOsVersion"`
	UsesNonExemptEncryption *bool  `json:"usesNonExemptEncryption"`
}

// ScreenshotSet represents a set of screenshots for a device type.
type ScreenshotSet struct {
	ID         string                  `json:"id"`
	Attributes ScreenshotSetAttributes `json:"attributes"`
}

type ScreenshotSetAttributes struct {
	ScreenshotDisplayType string `json:"screenshotDisplayType"`
}

// Generic API response wrappers.
type DataResponse[T any] struct {
	Data T `json:"data"`
}

type ListResponse[T any] struct {
	Data []T `json:"data"`
}

// GetApp fetches an app by its App Store Connect ID.
func (c *Client) GetApp(appID string) (*App, error) {
	var resp DataResponse[App]
	if err := c.get(fmt.Sprintf("/apps/%s", appID), &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetAppInfos fetches app info (age rating, state, etc).
func (c *Client) GetAppInfos(appID string) ([]AppInfo, error) {
	var resp ListResponse[AppInfo]
	if err := c.get(fmt.Sprintf("/apps/%s/appInfos", appID), &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// GetAppStoreVersions fetches all versions for an app.
func (c *Client) GetAppStoreVersions(appID string) ([]AppStoreVersion, error) {
	var resp ListResponse[AppStoreVersion]
	path := fmt.Sprintf("/apps/%s/appStoreVersions?filter[appStoreState]=READY_FOR_SALE,PREPARE_FOR_SUBMISSION,WAITING_FOR_REVIEW,IN_REVIEW,DEVELOPER_REJECTED", appID)
	if err := c.get(path, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// GetVersionLocalizations fetches localized metadata for a version.
func (c *Client) GetVersionLocalizations(versionID string) ([]VersionLocalization, error) {
	var resp ListResponse[VersionLocalization]
	if err := c.get(fmt.Sprintf("/appStoreVersions/%s/appStoreVersionLocalizations", versionID), &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// GetBuilds fetches builds for an app, optionally filtered.
func (c *Client) GetBuilds(appID string) ([]Build, error) {
	var resp ListResponse[Build]
	path := fmt.Sprintf("/builds?filter[app]=%s&sort=-uploadedDate&limit=5", appID)
	if err := c.get(path, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// GetScreenshotSets fetches screenshot sets for a version localization.
func (c *Client) GetScreenshotSets(localizationID string) ([]ScreenshotSet, error) {
	var resp ListResponse[ScreenshotSet]
	if err := c.get(fmt.Sprintf("/appStoreVersionLocalizations/%s/appScreenshotSets", localizationID), &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// Screenshot represents an individual screenshot file.
type Screenshot struct {
	ID         string               `json:"id"`
	Attributes ScreenshotAttributes `json:"attributes"`
}

type ScreenshotAttributes struct {
	FileSize         int         `json:"fileSize"`
	FileName         string      `json:"fileName"`
	ImageAsset       *ImageAsset `json:"imageAsset"`
	AssetToken       string      `json:"assetToken"`
	UploadOperations interface{} `json:"uploadOperations"`
}

type ImageAsset struct {
	Width  int `json:"width"`
	Height int `json:"height"`
}

// GetScreenshots fetches individual screenshots for a screenshot set.
func (c *Client) GetScreenshots(screenshotSetID string) ([]Screenshot, error) {
	var resp ListResponse[Screenshot]
	if err := c.get(fmt.Sprintf("/appScreenshotSets/%s/appScreenshots", screenshotSetID), &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// BetaGroup represents a TestFlight group.
type BetaGroup struct {
	ID         string              `json:"id"`
	Attributes BetaGroupAttributes `json:"attributes"`
}

type BetaGroupAttributes struct {
	Name                   string `json:"name"`
	IsInternalGroup        bool   `json:"isInternalGroup"`
	PublicLinkEnabled      *bool  `json:"publicLinkEnabled"`
	PublicLinkLimitEnabled *bool  `json:"publicLinkLimitEnabled"`
	HasAccessToAllBuilds   *bool  `json:"hasAccessToAllBuilds"`
}

// GetBetaGroups fetches TestFlight beta groups for an app.
func (c *Client) GetBetaGroups(appID string) ([]BetaGroup, error) {
	var resp ListResponse[BetaGroup]
	if err := c.get(fmt.Sprintf("/apps/%s/betaGroups", appID), &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// AppPrice represents an app's price schedule.
type AppPrice struct {
	ID         string             `json:"id"`
	Attributes AppPriceAttributes `json:"attributes"`
}

type AppPriceAttributes struct {
	Manual    bool   `json:"manual"`
	StartDate string `json:"startDate"`
}

// Territory represents an App Store territory.
type Territory struct {
	ID         string              `json:"id"`
	Attributes TerritoryAttributes `json:"attributes"`
}

type TerritoryAttributes struct {
	Currency string `json:"currency"`
}

// GetAppAvailability checks territory availability for an app.
func (c *Client) GetAppAvailability(appID string) ([]Territory, error) {
	var resp ListResponse[Territory]
	if err := c.get(fmt.Sprintf("/apps/%s/availableTerritories?limit=200", appID), &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// AppPricePoint represents a price tier.
type AppPricePoint struct {
	ID         string                  `json:"id"`
	Attributes AppPricePointAttributes `json:"attributes"`
}

type AppPricePointAttributes struct {
	CustomerPrice string `json:"customerPrice"`
	Proceeds      string `json:"proceeds"`
}

// GetAppPriceSchedule fetches the app's price schedule.
func (c *Client) GetAppPriceSchedule(appID string) ([]AppPrice, error) {
	var resp ListResponse[AppPrice]
	if err := c.get(fmt.Sprintf("/apps/%s/appPriceSchedule/manualPrices", appID), &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}
