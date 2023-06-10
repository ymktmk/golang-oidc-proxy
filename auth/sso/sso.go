package sso

import (
	"context"
	"crypto"
	// "log"

	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"

	"golang.org/x/oauth2"

	log "github.com/sirupsen/logrus"
	pkgrand "github.com/ymktmk/golang-sso-server/auth/rand"
	"github.com/ymktmk/golang-sso-server/auth/types"
	"github.com/ymktmk/golang-sso-server/config"

	"crypto/rsa"
	"crypto/x509"
)

const (
	Prefix = "Bearer v2:"
	issuer = "sso-server"
)

type Interface interface {
	Authorize(authorization string) (*types.Claims, error)
	HandleRedirect(w http.ResponseWriter, r *http.Request)
	HandleCallback(w http.ResponseWriter, r *http.Request)
}

type sso struct {
	config          *oauth2.Config
	issuer          string
	idTokenVerifier *oidc.IDTokenVerifier
	httpClient      *http.Client
	baseHRef        string
	secure          bool
	privateKey      crypto.PrivateKey
	encrypter       jose.Encrypter
	expiry          time.Duration
	customClaimName string
	userInfoPath    string
}

func NewSso(c config.SSOConfig) (Interface, error) {
	ctx := context.Background()
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: c.InsecureSkipVerify}, Proxy: http.ProxyFromEnvironment}}
	oidcContext := oidc.ClientContext(ctx, httpClient)
	if c.IssuerAlias != "" {
		oidcContext = oidc.InsecureIssuerURLContext(oidcContext, c.IssuerAlias)
	}

	// OpenID Connectプロバイダーを作成
	// https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration
	// https://login.microsoftonline.com/e377da87-4089-481c-b841-ffd8f01c060b/discovery/v2.0/keys?appid=6731de76-14a6-49ae-97bc-6eba6914391e
	provider, err := oidc.NewProvider(oidcContext, c.Issuer)
	if err != nil {
		return nil, err
	}

	// RSA鍵の生成
	generatedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(x509.MarshalPKCS1PrivateKey(generatedKey))
	if err != nil {
		return nil, fmt.Errorf("failed to private key: %w", err)
	}

	config := &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURL:  c.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       append(c.Scopes, oidc.ScopeOpenID),
	}

	// oidc
	idTokenVerifier := provider.Verifier(&oidc.Config{ClientID: config.ClientID})

	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.RSA_OAEP_256, Key: privateKey.Public()}, &jose.EncrypterOptions{Compression: jose.DEFLATE})
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT encrpytor: %w", err)
	}

	lf := log.Fields{"redirectUrl": config.RedirectURL, "issuer": c.Issuer, "issuerAlias": "DISABLED", "clientId": c.ClientID, "scopes": config.Scopes, "insecureSkipVerify": c.InsecureSkipVerify}
	if c.IssuerAlias != "" {
		lf["issuerAlias"] = c.IssuerAlias
	}

	return &sso{
		config:          config,
		idTokenVerifier: idTokenVerifier,
		httpClient:      httpClient,
		baseHRef:        "/",
		secure:          false,
		privateKey:      privateKey,
		encrypter:       encrypter,
		expiry:          c.GetSessionExpiry(),
		customClaimName: c.CustomGroupClaimName,
		userInfoPath:    c.UserInfoPath,
		issuer:          c.Issuer,
	}, nil
}

func (s *sso) HandleRedirect(w http.ResponseWriter, r *http.Request) {
	redirectUrl := r.URL.Query().Get("redirect")
	state, err := pkgrand.RandString(10)
	if err != nil {
		log.Println(err)
		w.WriteHeader(500)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     state,
		Value:    redirectUrl,
		Expires:  time.Now().Add(3 * time.Minute),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.secure,
	})

	redirectOption := oauth2.SetAuthURLParam("redirect_uri", s.getRedirectUrl(r))
	http.Redirect(w, r, s.config.AuthCodeURL(state, redirectOption), http.StatusFound)
}

func (s *sso) HandleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	state := r.URL.Query().Get("state")
	cookie, err := r.Cookie(state)
	http.SetCookie(w, &http.Cookie{Name: state, MaxAge: 0})
	if err != nil {
		w.WriteHeader(400)
		return
	}
	redirectOption := oauth2.SetAuthURLParam("redirect_uri", s.getRedirectUrl(r))

	oauth2Context := context.WithValue(ctx, oauth2.HTTPClient, s.httpClient)
	oauth2Token, err := s.config.Exchange(oauth2Context, r.URL.Query().Get("code"), redirectOption)
	if err != nil {
		w.WriteHeader(401)
		return
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		w.WriteHeader(401)
		return
	}

	// https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-key-sets
	// https://login.microsoftonline.com/common/discovery/keys
	// https://login.microsoftonline.com/e377da87-4089-481c-b841-ffd8f01c060b/discovery/v2.0/keys
	idToken, err := s.idTokenVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		log.Println(err)
		w.WriteHeader(401)
		return
	}
	c := &types.Claims{}
	if err := idToken.Claims(c); err != nil {
		w.WriteHeader(401)
		return
	}

	// Default to groups claim but if customClaimName is set
	// extract groups based on that claim key
	groups := c.Groups
	if s.customClaimName != "" {
		groups, err = c.GetCustomGroup(s.customClaimName)
		if err != nil {
			w.WriteHeader(401)
			return
		}
	}

	// Some SSO implementations (Okta) require a call to
	// the OIDC user info path to get attributes like groups
	if s.userInfoPath != "" {
		groups, err = c.GetUserInfoGroups(oauth2Token.AccessToken, s.issuer, s.userInfoPath)
		if err != nil {
			log.Println(err)
			w.WriteHeader(401)
			return
		}
	}

	claims := &types.Claims{
		Claims: jwt.Claims{
			Issuer:  issuer,
			Subject: c.Subject,
			Expiry:  jwt.NewNumericDate(time.Now().Add(s.expiry)),
		},
		Groups:            groups,
		Email:             c.Email,
		EmailVerified:     c.EmailVerified,
		Name:              c.Name,
		PreferredUsername: c.PreferredUsername,
	}

	// encrypter
	raw, err := jwt.Encrypted(s.encrypter).Claims(claims).CompactSerialize()
	if err != nil {
		log.Println(err)
		w.WriteHeader(401)
		return
	}
	value := Prefix + raw

	http.SetCookie(w, &http.Cookie{
		Value:    value,
		Name:     "authorization",
		Path:     s.baseHRef,
		Expires:  time.Now().Add(s.expiry),
		SameSite: http.SameSiteStrictMode,
		Secure:   s.secure,
	})
	redirect := s.baseHRef

	proto := "http"
	if s.secure {
		proto = "https"
	}

	prefix := fmt.Sprintf("%s://%s%s", proto, r.Host, s.baseHRef)

	if strings.HasPrefix(cookie.Value, prefix) {
		redirect = cookie.Value
	}
	http.Redirect(w, r, redirect, 302)
}

func (s *sso) Authorize(authorization string) (*types.Claims, error) {
	tok, err := jwt.ParseEncrypted(strings.TrimPrefix(authorization, Prefix))
	if err != nil {
		return nil, fmt.Errorf("failed to parse encrypted token %v", err)
	}
	c := &types.Claims{}
	// privateKey
	if err := tok.Claims(s.privateKey, c); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %v", err)
	}

	if err := c.Validate(jwt.Expected{Issuer: issuer}); err != nil {
		return nil, fmt.Errorf("failed to validate claims: %v", err)
	}

	return c, nil
}

func (s *sso) getRedirectUrl(r *http.Request) string {
	if s.config.RedirectURL != "" {
		return s.config.RedirectURL
	}

	proto := "http"

	if r.URL.Scheme != "" {
		proto = r.URL.Scheme
	} else if s.secure {
		proto = "https"
	}

	return fmt.Sprintf("%s://%s%soauth2/callback", proto, r.Host, s.baseHRef)
}
