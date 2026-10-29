package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/RevylAI/greenlight/internal/asc"
	"github.com/RevylAI/greenlight/internal/config"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Manage App Store Connect authentication",
}

var authLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Log in with your Apple ID (recommended)",
	Long: `Sign in with your Apple ID and password, just like you would
on the App Store Connect website. Supports two-factor authentication.

Your credentials are only sent to Apple — never stored or sent anywhere else.
The session is saved locally at ~/.greenlight/config.json.`,
	RunE: runAuthLogin,
}

var authSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Configure with App Store Connect API key (advanced)",
	Long: `Set up authentication using an App Store Connect API key.

You need an API key from App Store Connect:
  1. Go to App Store Connect → Users and Access → Integrations → Keys
  2. Generate a new key with "App Manager" or higher access
  3. Download the .p8 private key file
  4. Note the Key ID and Issuer ID`,
	RunE: runAuthSetup,
}

var authStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current authentication status",
	RunE:  runAuthStatus,
}

var authLogoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Remove stored credentials",
	RunE:  runAuthLogout,
}

func init() {
	authCmd.AddCommand(authLoginCmd)
	authCmd.AddCommand(authSetupCmd)
	authCmd.AddCommand(authStatusCmd)
	authCmd.AddCommand(authLogoutCmd)
}

func runAuthLogin(cmd *cobra.Command, args []string) error {
	reader := bufio.NewReader(os.Stdin)

	purple.Println("\n  greenlight auth login")
	fmt.Println("  Sign in with your Apple ID.")
	fmt.Println("  Your credentials are sent directly to Apple — never stored or shared.")

	// Apple ID
	fmt.Print("  Apple ID (email): ")
	appleID, _ := reader.ReadString('\n')
	appleID = strings.TrimSpace(appleID)
	if appleID == "" {
		return fmt.Errorf("Apple ID is required")
	}

	// Password (hidden input)
	fmt.Print("  Password: ")
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println() // newline after hidden input
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	password := string(passwordBytes)
	if password == "" {
		return fmt.Errorf("password is required")
	}

	// Attempt sign-in
	fmt.Println()
	dim.Println("  Signing in...")

	session, err := asc.SignIn(appleID, password)
	if err != nil {
		// Check if 2FA is required
		twoFA, ok := err.(*asc.TwoFactorRequired)
		if !ok {
			return fmt.Errorf("sign-in failed: %w", err)
		}

		// 2FA flow
		session = twoFA.Session
		fmt.Println()
		purple.Println("  Two-factor authentication required.")
		fmt.Println("  A code has been sent to your trusted devices.")
		fmt.Print("  6-digit code: ")
		code, _ := reader.ReadString('\n')
		code = strings.TrimSpace(code)

		fmt.Println()
		dim.Println("  Verifying...")

		if err := session.SubmitTwoFactorCode(code); err != nil {
			return fmt.Errorf("2FA verification failed: %w", err)
		}
	}

	// Get session info
	dim.Println("  Fetching account info...")
	sessionInfo, err := session.GetSessionInfo()
	if err != nil {
		// Session may still work even if we can't get info
		fmt.Printf("  Warning: could not fetch session info: %v\n", err)
	}

	// Save to config
	cookies := session.SerializeCookies()
	var configCookies []*config.SerializedCookie
	for _, c := range cookies {
		configCookies = append(configCookies, &config.SerializedCookie{
			Name:   c.Name,
			Value:  c.Value,
			Domain: c.Domain,
			Path:   c.Path,
		})
	}

	cfg := &config.Config{
		AuthMethod: config.AuthMethodSession,
		Session: &config.SessionConfig{
			AppleID:    appleID,
			SessionID:  session.SessionID,
			Scnt:       session.Scnt,
			Cookies:    configCookies,
			TeamID:     session.TeamID,
			ProviderID: session.ProviderID,
			ExpiresAt:  session.ExpiresAt,
		},
	}

	if err := config.Save(cfg); err != nil {
		return fmt.Errorf("failed to save session: %w", err)
	}

	fmt.Println()
	purple.Println("  ✓ Logged in successfully!")
	if sessionInfo != nil {
		fmt.Printf("  Account: %s (%s)\n", sessionInfo.User.FullName, sessionInfo.User.Email)
		if sessionInfo.Provider.Name != "" {
			fmt.Printf("  Team:    %s\n", sessionInfo.Provider.Name)
		}
	}
	fmt.Println()
	fmt.Println("  Run 'greenlight preflight .' to scan your project now.")
	fmt.Println("  'greenlight scan --app-id YOUR_APP_ID' needs an App Store Connect API")
	fmt.Println("  key — this Apple ID session can't call that API. Run 'greenlight auth")
	fmt.Println("  setup' if you want the --app-id tier too.")
	fmt.Println()

	return nil
}

func runAuthSetup(cmd *cobra.Command, args []string) error {
	reader := bufio.NewReader(os.Stdin)

	purple.Println("\n  greenlight auth setup")
	fmt.Println("  Configure App Store Connect API key credentials.")
	fmt.Println("  Generate a key at: App Store Connect → Users and Access → Keys")

	fmt.Print("  Key ID: ")
	keyID, _ := reader.ReadString('\n')
	keyID = strings.TrimSpace(keyID)

	fmt.Print("  Issuer ID: ")
	issuerID, _ := reader.ReadString('\n')
	issuerID = strings.TrimSpace(issuerID)

	fmt.Print("  Path to .p8 private key: ")
	keyPath, _ := reader.ReadString('\n')
	keyPath = strings.TrimSpace(keyPath)

	if strings.HasPrefix(keyPath, "~/") {
		home, _ := os.UserHomeDir()
		keyPath = home + keyPath[1:]
	}

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return fmt.Errorf("private key file not found: %s", keyPath)
	}

	cfg := &config.Config{
		AuthMethod:     config.AuthMethodAPIKey,
		KeyID:          keyID,
		IssuerID:       issuerID,
		PrivateKeyPath: keyPath,
	}

	if err := config.Save(cfg); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Println()
	purple.Println("  ✓ API key credentials saved!")
	fmt.Println("  Run 'greenlight scan --app-id YOUR_APP_ID' to start scanning.")
	fmt.Println()

	return nil
}

func runAuthStatus(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		fmt.Println("\n  Not authenticated.")
		fmt.Println("  Run 'greenlight auth login' (Apple ID) or 'greenlight auth setup' (API key).")
		return nil
	}

	purple.Println("\n  greenlight auth status")

	switch cfg.AuthMethod {
	case config.AuthMethodSession:
		fmt.Println("  Method:  Apple ID session")
		if cfg.Session != nil {
			fmt.Printf("  Account: %s\n", cfg.Session.AppleID)
			if cfg.Session.TeamID != "" {
				fmt.Printf("  Team:    %s\n", cfg.Session.TeamID)
			}
			if cfg.Session.ExpiresAt.After(time.Now()) {
				fmt.Printf("  Expires: %s\n", cfg.Session.ExpiresAt.Format("Jan 2, 2006"))
			} else {
				fmt.Println("  Status:  EXPIRED — run 'greenlight auth login' to re-authenticate")
			}
		}

	case config.AuthMethodAPIKey:
		fmt.Println("  Method:     API Key")
		fmt.Printf("  Key ID:     %s\n", cfg.KeyID)
		fmt.Printf("  Issuer ID:  %s\n", cfg.IssuerID)
		fmt.Printf("  Key Path:   %s\n", cfg.PrivateKeyPath)

	default:
		fmt.Println("  Unknown auth method. Run 'greenlight auth login' to set up.")
	}

	fmt.Println()
	return nil
}

func runAuthLogout(cmd *cobra.Command, args []string) error {
	dir, err := config.ConfigDir()
	if err != nil {
		return err
	}

	path := dir + "/config.json"
	if _, err := os.Stat(path); os.IsNotExist(err) {
		fmt.Println("\n  Not authenticated — nothing to remove.")
		return nil
	}

	if err := os.Remove(path); err != nil {
		return fmt.Errorf("failed to remove credentials: %w", err)
	}

	purple.Println("\n  ✓ Logged out. Credentials removed.")
	return nil
}
