package config

import (
	"fmt"
	"os"
	"time"
)

type SSOConfig struct {
	Issuer               string        `json:"issuer"`
	IssuerAlias          string        `json:"issuerAlias,omitempty"`
	ClientID             string        `json:"clientId"`
	ClientSecret         string        `json:"clientSecret"`
	RedirectURL          string        `json:"redirectUrl"`
	Scopes               []string      `json:"scopes,omitempty"`
	SessionExpiry        time.Duration `json:"sessionExpiry,omitempty"`
	CustomGroupClaimName string        `json:"customGroupClaimName,omitempty"`
	UserInfoPath         string        `json:"userInfoPath,omitempty"`
	InsecureSkipVerify   bool          `json:"insecureSkipVerify,omitempty"`
}

func NewSsoConfig() (SSOConfig, error) {
	config := &SSOConfig{}

	config.Issuer = os.Getenv("ISSUER")
	if config.Issuer == "" {
		return SSOConfig{}, fmt.Errorf("the ISSUER has not been set")
	}

	config.ClientID = os.Getenv("CLIENT_ID")
	if config.ClientID == "" {
		return SSOConfig{}, fmt.Errorf("the CLIENT_ID has not been set")
	}

	config.ClientSecret = os.Getenv("CLIENT_SECRET")
	if config.ClientSecret == "" {
		return SSOConfig{}, fmt.Errorf("the CLIENT_SECRET has not been set")
	}

	config.RedirectURL = os.Getenv("REDIRECT_URL")
	if config.RedirectURL == "" {
		return SSOConfig{}, fmt.Errorf("the REDIRECT_URL has not been set")
	}

	return SSOConfig{
		Issuer:               config.Issuer,
		ClientID:             config.ClientID,
		ClientSecret:         config.ClientSecret,
		RedirectURL:          config.RedirectURL,
		Scopes:               []string{"profile", "email"},
		SessionExpiry:        10 * time.Hour,
		CustomGroupClaimName: "",
		UserInfoPath:         "", // https://graph.microsoft.com/oidc/userinfo 入れると落ちる
		InsecureSkipVerify:   true,
	}, nil
}

func (c SSOConfig) GetSessionExpiry() time.Duration {
	if c.SessionExpiry > 0 {
		return c.SessionExpiry
	}
	return 10 * time.Hour
}
