package asc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"
)

const (
	appleAuthURL  = "https://idmsa.apple.com/appleauth/auth"
	ascSessionURL = "https://appstoreconnect.apple.com/olympus/v1/session"
)

// Session holds Apple ID session state for authenticated requests.
type Session struct {
	AppleID    string              `json:"apple_id"`
	SessionID  string              `json:"session_id"`
	Scnt       string              `json:"scnt"`
	Cookies    []*SerializedCookie `json:"cookies"`
	TeamID     string              `json:"team_id,omitempty"`
	ProviderID string              `json:"provider_id,omitempty"`
	ExpiresAt  time.Time           `json:"expires_at"`
	httpClient *http.Client
}

// SerializedCookie is a JSON-safe cookie representation.
type SerializedCookie struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Domain string `json:"domain"`
	Path   string `json:"path"`
}

// SignInRequest is the Apple ID login payload.
type SignInRequest struct {
	AccountName string `json:"accountName"`
	Password    string `json:"password"`
	RememberMe  bool   `json:"rememberMe"`
}

// AuthResponse from Apple's sign-in endpoint.
type AuthResponse struct {
	AuthType string `json:"authType"` // "hsa2" for 2FA
}

// TwoFactorInfo returned when 2FA is required.
type TwoFactorInfo struct {
	TrustedDevices []struct {
		ID          int    `json:"id"`
		PhoneNumber string `json:"phoneNumber"`
	} `json:"trustedDevices"`
}

// SessionInfo from the App Store Connect session endpoint.
type SessionInfo struct {
	User struct {
		FullName string `json:"fullName"`
		Email    string `json:"emailAddress"`
	} `json:"user"`
	Provider struct {
		ProviderID  int    `json:"providerId"`
		Name        string `json:"name"`
		PublicKeyID string `json:"publicKeyId"`
	} `json:"provider"`
	AvailableProviders []struct {
		ProviderID int    `json:"providerId"`
		Name       string `json:"name"`
	} `json:"availableProviders"`
}

// commonHeaders returns the headers Apple expects for auth requests.
func commonHeaders() map[string]string {
	return map[string]string{
		"Content-Type":       "application/json",
		"Accept":             "application/json",
		"X-Requested-With":   "XMLHttpRequest",
		"X-Apple-Widget-Key": "e0b80c3bf78523bfe80571b6ff2e766c", // Public widget key used by ASC web
		"User-Agent":         "greenlight/1.0",
	}
}

// SignIn authenticates with Apple ID and password.
// Returns a session if successful, or an error indicating 2FA is needed.
func SignIn(appleID, password string) (*Session, error) {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar:     jar,
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	payload := SignInRequest{
		AccountName: appleID,
		Password:    password,
		RememberMe:  true,
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", appleAuthURL+"/signin", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	for k, v := range commonHeaders() {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sign-in request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	session := &Session{
		AppleID:    appleID,
		SessionID:  resp.Header.Get("X-Apple-Id-Session-Id"),
		Scnt:       resp.Header.Get("scnt"),
		httpClient: client,
	}

	switch resp.StatusCode {
	case 200:
		// No 2FA needed (rare)
		session.ExpiresAt = time.Now().Add(24 * time.Hour)
		return session, nil

	case 409:
		// 2FA required — this is the normal path
		return session, &TwoFactorRequired{Session: session}

	case 401:
		return nil, fmt.Errorf("invalid Apple ID or password")

	case 403:
		return nil, fmt.Errorf("account locked or requires web sign-in first. Go to appleid.apple.com to unlock")

	case 412:
		return nil, fmt.Errorf("terms and conditions need to be accepted. Sign in at developer.apple.com first")

	default:
		return nil, fmt.Errorf("unexpected response %d: %s", resp.StatusCode, string(respBody))
	}
}

// TwoFactorRequired is returned when 2FA is needed.
type TwoFactorRequired struct {
	Session *Session
}

func (e *TwoFactorRequired) Error() string {
	return "two-factor authentication required"
}

// SubmitTwoFactorCode sends the 6-digit 2FA code to Apple.
func (s *Session) SubmitTwoFactorCode(code string) error {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return fmt.Errorf("code must be 6 digits")
	}

	payload := map[string]interface{}{
		"securityCode": map[string]string{
			"code": code,
		},
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", appleAuthURL+"/verify/trusteddevice/securitycode", bytes.NewReader(body))
	if err != nil {
		return err
	}

	for k, v := range commonHeaders() {
		req.Header.Set(k, v)
	}
	req.Header.Set("X-Apple-Id-Session-Id", s.SessionID)
	req.Header.Set("scnt", s.Scnt)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("2FA verification failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 400 {
		return fmt.Errorf("incorrect verification code")
	}
	if resp.StatusCode != 204 && resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("2FA verification returned %d: %s", resp.StatusCode, string(respBody))
	}

	// Update session headers from response
	if sid := resp.Header.Get("X-Apple-Id-Session-Id"); sid != "" {
		s.SessionID = sid
	}
	if scnt := resp.Header.Get("scnt"); scnt != "" {
		s.Scnt = scnt
	}

	// Trust the session
	if err := s.trustSession(); err != nil {
		return fmt.Errorf("failed to trust session: %w", err)
	}

	s.ExpiresAt = time.Now().Add(30 * 24 * time.Hour) // Sessions last ~30 days
	return nil
}

// trustSession tells Apple to remember this device.
func (s *Session) trustSession() error {
	req, err := http.NewRequest("GET", appleAuthURL+"/2sv/trust", nil)
	if err != nil {
		return err
	}

	for k, v := range commonHeaders() {
		req.Header.Set(k, v)
	}
	req.Header.Set("X-Apple-Id-Session-Id", s.SessionID)
	req.Header.Set("scnt", s.Scnt)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Update session from response
	if sid := resp.Header.Get("X-Apple-Id-Session-Id"); sid != "" {
		s.SessionID = sid
	}
	if scnt := resp.Header.Get("scnt"); scnt != "" {
		s.Scnt = scnt
	}

	return nil
}

// GetSessionInfo fetches the authenticated user's App Store Connect session.
func (s *Session) GetSessionInfo() (*SessionInfo, error) {
	req, err := http.NewRequest("GET", ascSessionURL, nil)
	if err != nil {
		return nil, err
	}

	for k, v := range commonHeaders() {
		req.Header.Set(k, v)
	}
	req.Header.Set("X-Apple-Id-Session-Id", s.SessionID)
	req.Header.Set("scnt", s.Scnt)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("session request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("session returned %d: %s", resp.StatusCode, string(body))
	}

	var info SessionInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("failed to parse session: %w", err)
	}

	s.ProviderID = fmt.Sprintf("%d", info.Provider.ProviderID)
	s.TeamID = info.Provider.Name

	return &info, nil
}

// SerializeCookies extracts cookies for persistent storage.
func (s *Session) SerializeCookies() []*SerializedCookie {
	if s.httpClient == nil || s.httpClient.Jar == nil {
		return nil
	}

	// Get cookies from known Apple domains
	var cookies []*SerializedCookie
	domains := []string{
		"https://idmsa.apple.com",
		"https://appstoreconnect.apple.com",
		"https://apple.com",
	}

	for _, domain := range domains {
		u, _ := http.NewRequest("GET", domain, nil)
		if u == nil {
			continue
		}
		for _, c := range s.httpClient.Jar.Cookies(u.URL) {
			cookies = append(cookies, &SerializedCookie{
				Name:   c.Name,
				Value:  c.Value,
				Domain: u.URL.Host,
				Path:   c.Path,
			})
		}
	}

	return cookies
}
