package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coroot/coroot/db"
	"github.com/coroot/coroot/rbac"
	"k8s.io/klog"
)

// GitLabOIDCConfig holds the configuration for GitLab OIDC authentication
type GitLabOIDCConfig struct {
	Enabled      bool          `json:"enabled"`
	URL          string        `json:"url"`           // GitLab instance URL
	ClientID     string        `json:"client_id"`     // OAuth2 Client ID
	ClientSecret string        `json:"client_secret"` // OAuth2 Client Secret (hidden in responses)
	DefaultRole  rbac.RoleName `json:"default_role"`
}

// GitLabUserInfo represents the user information returned by GitLab's userinfo endpoint
type GitLabUserInfo struct {
	Sub               string   `json:"sub"`
	Name              string   `json:"name"`
	Nickname          string   `json:"nickname"`
	PreferredUsername string   `json:"preferred_username"`
	Email             string   `json:"email"`
	EmailVerified     bool     `json:"email_verified"`
	Profile           string   `json:"profile"`
	Picture           string   `json:"picture"`
	Groups            []string `json:"groups"`
}

// GitLabTokenResponse represents the token response from GitLab's OAuth2 token endpoint
type GitLabTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token"`
}

const (
	gitlabOIDCStateCookieName = "coroot_gitlab_oidc_state"
	gitlabOIDCStateTTL        = 10 * time.Minute
)

// generateOIDCState generates a random state string for OIDC authentication
func generateOIDCState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// GitLabOIDCLogin initiates the GitLab OIDC authentication flow
func (api *Api) GitLabOIDCLogin(w http.ResponseWriter, r *http.Request) {
	config := api.getGitLabOIDCConfig()
	if config == nil || !config.Enabled {
		http.Error(w, "GitLab OIDC is not configured", http.StatusBadRequest)
		return
	}

	state, err := generateOIDCState()
	if err != nil {
		klog.Errorln("failed to generate OIDC state:", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	// Store state in a cookie for validation
	http.SetCookie(w, &http.Cookie{
		Name:     gitlabOIDCStateCookieName,
		Value:    state,
		Path:     "/",
		Expires:  time.Now().Add(gitlabOIDCStateTTL),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	// Build GitLab authorization URL
	authURL, err := url.Parse(strings.TrimSuffix(config.URL, "/") + "/oauth/authorize")
	if err != nil {
		klog.Errorln("failed to parse GitLab URL:", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	// Get the redirect URI (callback URL)
	redirectURI := api.getGitLabOIDCRedirectURI(r)

	q := authURL.Query()
	q.Set("client_id", config.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	q.Set("scope", "openid profile email")
	q.Set("state", state)
	authURL.RawQuery = q.Encode()

	http.Redirect(w, r, authURL.String(), http.StatusFound)
}

// GitLabOIDCCallback handles the OAuth2 callback from GitLab
func (api *Api) GitLabOIDCCallback(w http.ResponseWriter, r *http.Request) {
	config := api.getGitLabOIDCConfig()
	if config == nil || !config.Enabled {
		http.Error(w, "GitLab OIDC is not configured", http.StatusBadRequest)
		return
	}

	// Check for errors from GitLab
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		errDesc := r.URL.Query().Get("error_description")
		klog.Warningln("GitLab OIDC error:", errParam, errDesc)
		http.Redirect(w, r, api.urlBasePath+"sso/gitlab?error="+url.QueryEscape(errParam), http.StatusFound)
		return
	}

	// Validate state
	stateCookie, err := r.Cookie(gitlabOIDCStateCookieName)
	if err != nil {
		klog.Warningln("missing OIDC state cookie")
		http.Redirect(w, r, api.urlBasePath+"sso/gitlab?error=invalid_state", http.StatusFound)
		return
	}

	state := r.URL.Query().Get("state")
	if state != stateCookie.Value {
		klog.Warningln("invalid OIDC state")
		http.Redirect(w, r, api.urlBasePath+"sso/gitlab?error=invalid_state", http.StatusFound)
		return
	}

	// Clear state cookie
	http.SetCookie(w, &http.Cookie{
		Name:     gitlabOIDCStateCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
	})

	// Get authorization code
	code := r.URL.Query().Get("code")
	if code == "" {
		klog.Warningln("missing authorization code")
		http.Redirect(w, r, api.urlBasePath+"sso/gitlab?error=missing_code", http.StatusFound)
		return
	}

	// Exchange code for tokens
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	token, err := api.exchangeGitLabCode(ctx, config, code, api.getGitLabOIDCRedirectURI(r))
	if err != nil {
		klog.Errorln("failed to exchange GitLab code:", err)
		http.Redirect(w, r, api.urlBasePath+"sso/gitlab?error=token_exchange", http.StatusFound)
		return
	}

	// Get user info
	userInfo, err := api.getGitLabUserInfo(ctx, config, token.AccessToken)
	if err != nil {
		klog.Errorln("failed to get GitLab user info:", err)
		http.Redirect(w, r, api.urlBasePath+"sso/gitlab?error=user_info", http.StatusFound)
		return
	}

	// Create or update user
	user, err := api.createOrUpdateGitLabUser(userInfo, config.DefaultRole)
	if err != nil {
		klog.Errorln("failed to create/update user:", err)
		http.Redirect(w, r, api.urlBasePath+"sso/gitlab?error=user_creation", http.StatusFound)
		return
	}

	// Set session cookie
	if err := api.SetSessionCookie(w, user.Id, SessionCookieTTL); err != nil {
		klog.Errorln("failed to set session cookie:", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	// Redirect to home page
	http.Redirect(w, r, api.urlBasePath, http.StatusFound)
}

// exchangeGitLabCode exchanges the authorization code for an access token
func (api *Api) exchangeGitLabCode(ctx context.Context, config *GitLabOIDCConfig, code, redirectURI string) (*GitLabTokenResponse, error) {
	tokenURL := strings.TrimSuffix(config.URL, "/") + "/oauth/token"

	data := url.Values{}
	data.Set("client_id", config.ClientID)
	data.Set("client_secret", config.ClientSecret)
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", redirectURI)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var token GitLabTokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return &token, nil
}

// getGitLabUserInfo retrieves user information from GitLab's userinfo endpoint
func (api *Api) getGitLabUserInfo(ctx context.Context, config *GitLabOIDCConfig, accessToken string) (*GitLabUserInfo, error) {
	userInfoURL := strings.TrimSuffix(config.URL, "/") + "/oauth/userinfo"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute userinfo request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read userinfo response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var userInfo GitLabUserInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("failed to parse userinfo response: %w", err)
	}

	return &userInfo, nil
}

// createOrUpdateGitLabUser creates or updates a user based on GitLab user info
func (api *Api) createOrUpdateGitLabUser(userInfo *GitLabUserInfo, defaultRole rbac.RoleName) (*db.User, error) {
	if userInfo.Email == "" {
		return nil, errors.New("email is required from GitLab")
	}

	// Try to find existing user by email
	users, err := api.db.GetUsers()
	if err != nil {
		return nil, fmt.Errorf("failed to get users: %w", err)
	}

	var existingUser *db.User
	for _, u := range users {
		if strings.EqualFold(u.Email, userInfo.Email) {
			existingUser = u
			break
		}
	}

	name := userInfo.Name
	if name == "" {
		name = userInfo.PreferredUsername
	}
	if name == "" {
		name = userInfo.Nickname
	}
	if name == "" {
		name = userInfo.Email
	}

	if existingUser != nil {
		// User exists - return it without modifying
		return existingUser, nil
	}

	// Create new user
	if defaultRole == "" {
		defaultRole = rbac.RoleViewer
	}

	if err := api.db.AddUser(userInfo.Email, "", name, defaultRole); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Get the created user
	users, err = api.db.GetUsers()
	if err != nil {
		return nil, fmt.Errorf("failed to get users after creation: %w", err)
	}

	for _, u := range users {
		if strings.EqualFold(u.Email, userInfo.Email) {
			return u, nil
		}
	}

	return nil, errors.New("failed to find created user")
}

// getGitLabOIDCRedirectURI builds the redirect URI for GitLab OIDC callback
func (api *Api) getGitLabOIDCRedirectURI(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		if fwdProto := r.Header.Get("X-Forwarded-Proto"); fwdProto != "" {
			scheme = fwdProto
		} else {
			scheme = "http"
		}
	}

	host := r.Host
	if fwdHost := r.Header.Get("X-Forwarded-Host"); fwdHost != "" {
		host = fwdHost
	}

	return fmt.Sprintf("%s://%s%ssso/gitlab/callback", scheme, host, api.urlBasePath)
}

// getGitLabOIDCConfig returns the GitLab OIDC configuration
func (api *Api) getGitLabOIDCConfig() *GitLabOIDCConfig {
	if api.gitLabOIDC == nil {
		return nil
	}
	return api.gitLabOIDC
}

// GitLabOIDCSettings handles GET/POST requests for GitLab OIDC settings
func (api *Api) GitLabOIDCSettings(w http.ResponseWriter, r *http.Request, u *db.User) {
	roles, err := api.roles.GetRoles()
	if err != nil {
		klog.Errorln(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	if r.Method == http.MethodGet {
		res := struct {
			Enabled     bool            `json:"enabled"`
			URL         string          `json:"url"`
			ClientID    string          `json:"client_id"`
			DefaultRole rbac.RoleName   `json:"default_role"`
			Roles       []rbac.RoleName `json:"roles"`
			Readonly    bool            `json:"readonly"`
		}{
			DefaultRole: rbac.RoleViewer,
			Readonly:    api.gitLabOIDCReadonly,
		}

		for _, role := range roles {
			res.Roles = append(res.Roles, role.Name)
		}

		if api.gitLabOIDC != nil {
			res.Enabled = api.gitLabOIDC.Enabled
			res.URL = api.gitLabOIDC.URL
			res.ClientID = api.gitLabOIDC.ClientID
			res.DefaultRole = api.gitLabOIDC.DefaultRole
		}

		json.NewEncoder(w).Encode(res)
		return
	}

	// POST - update settings (only if not readonly)
	if api.gitLabOIDCReadonly {
		http.Error(w, "GitLab OIDC is configured through config file and cannot be modified via UI", http.StatusForbidden)
		return
	}

	if !api.IsAllowed(u, rbac.Actions.Users().Edit()) {
		http.Error(w, "You are not allowed to configure GitLab OIDC.", http.StatusForbidden)
		return
	}

	var form struct {
		Action       string        `json:"action"`
		URL          string        `json:"url"`
		ClientID     string        `json:"client_id"`
		ClientSecret string        `json:"client_secret"`
		DefaultRole  rbac.RoleName `json:"default_role"`
	}

	if err := json.NewDecoder(r.Body).Decode(&form); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	switch form.Action {
	case "save":
		if form.URL == "" || form.ClientID == "" {
			http.Error(w, "URL and Client ID are required", http.StatusBadRequest)
			return
		}

		// Validate the role
		if !form.DefaultRole.Valid(roles) {
			http.Error(w, "Invalid default role", http.StatusBadRequest)
			return
		}

		config := &GitLabOIDCConfig{
			Enabled:     true,
			URL:         strings.TrimSuffix(form.URL, "/"),
			ClientID:    form.ClientID,
			DefaultRole: form.DefaultRole,
		}

		// Only update secret if provided
		if form.ClientSecret != "" {
			config.ClientSecret = form.ClientSecret
		} else if api.gitLabOIDC != nil {
			config.ClientSecret = api.gitLabOIDC.ClientSecret
		}

		if config.ClientSecret == "" {
			http.Error(w, "Client Secret is required", http.StatusBadRequest)
			return
		}

		api.gitLabOIDC = config

		// Save to database
		if err := api.db.SetSetting("gitlab_oidc", config); err != nil {
			klog.Errorln("failed to save GitLab OIDC config:", err)
			http.Error(w, "", http.StatusInternalServerError)
			return
		}

	case "disable":
		if api.gitLabOIDC != nil {
			api.gitLabOIDC.Enabled = false
			if err := api.db.SetSetting("gitlab_oidc", api.gitLabOIDC); err != nil {
				klog.Errorln("failed to save GitLab OIDC config:", err)
				http.Error(w, "", http.StatusInternalServerError)
				return
			}
		}

	default:
		http.Error(w, "Unknown action", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// InitGitLabOIDC initializes the GitLab OIDC configuration from config file and/or database
func (api *Api) InitGitLabOIDC(urlBasePath string, configOIDC *GitLabOIDCConfig) error {
	api.urlBasePath = urlBasePath

	// If configured via config file, use that (readonly mode)
	if configOIDC != nil && configOIDC.URL != "" && configOIDC.ClientID != "" && configOIDC.ClientSecret != "" {
		api.gitLabOIDC = configOIDC
		api.gitLabOIDCReadonly = true
		klog.Infoln("GitLab OIDC initialized from config file (readonly mode)")
		return nil
	}

	// Otherwise, try to load from database
	var dbConfig GitLabOIDCConfig
	err := api.db.GetSetting("gitlab_oidc", &dbConfig)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			// No config found, that's ok
			return nil
		}
		return fmt.Errorf("failed to load GitLab OIDC config from database: %w", err)
	}

	api.gitLabOIDC = &dbConfig
	api.gitLabOIDCReadonly = false
	klog.Infoln("GitLab OIDC initialized from database")
	return nil
}
