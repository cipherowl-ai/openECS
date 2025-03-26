package reload

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// RemoteClient defines the interface for all remote operations
type RemoteClient interface {
	// FetchMetadata retrieves the bloom filter metadata for the given chain and dataset
	FetchMetadata(chain, dataset string) (*EcsDataset, error)
	// DownloadFile downloads the file from the given URL to the destination path
	DownloadFile(ctx context.Context, url string, dest string) error
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
}

// Default implementation of RemoteClient
type defaultRemoteClient struct {
	baseURL      string
	clientID     string
	clientSecret string
	httpClient   *http.Client
	accessToken  string
	tokenExpires time.Time
	mu           sync.RWMutex
	logger       *slog.Logger
}

func NewRemoteClient(baseURL, clientID, clientSecret string, logger *slog.Logger) RemoteClient {
	if logger == nil {
		logger = slog.Default()
	}

	return &defaultRemoteClient{
		baseURL:      baseURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		mu:           sync.RWMutex{},
		logger:       logger,
	}
}

func (c *defaultRemoteClient) getAccessToken() (string, error) {
	cachedToken, err := c.getCachedToken()
	if err == nil {
		return cachedToken, nil
	}

	refreshToken, err := c.refreshAccessToken()
	if err != nil {
		return "", fmt.Errorf("failed to refresh access token: %w", err)
	}

	return refreshToken, nil
}

func (c *defaultRemoteClient) getCachedToken() (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.accessToken != "" && c.tokenExpires.After(time.Now()) {
		return c.accessToken, nil
	}

	return "", fmt.Errorf("no cached token available")
}

func (c *defaultRemoteClient) refreshAccessToken() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.accessToken != "" && c.tokenExpires.After(time.Now()) {
		return c.accessToken, nil
	}

	c.logger.Debug("refreshing access token")
	tokenURL := fmt.Sprintf("%s/oauth/token", c.baseURL)

	// Get the audience from the baseURL, remove the scheme and port
	audience := strings.TrimSuffix(c.baseURL, "/")
	audience = strings.TrimPrefix(audience, "https://")
	audience = strings.TrimPrefix(audience, "http://")

	payload := map[string]string{
		"client_id":     c.clientID,
		"client_secret": c.clientSecret,
		"audience":      audience,
		"grant_type":    "client_credentials",
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		c.logger.Error("failed to marshal token request payload", "error", err)
		return "", fmt.Errorf("error marshalling payload: %w", err)
	}

	req, err := http.NewRequest("POST", tokenURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		c.logger.Error("failed to create token request", "error", err)
		return "", fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Error("failed to make token request", "error", err)
		return "", fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.logger.Error("unexpected status code from token request",
			"statusCode", resp.StatusCode,
		)
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var tokenResponse TokenResponse

	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		c.logger.Error("error decoding token response", "error", err)
		return "", fmt.Errorf("error decoding response: %w", err)
	}

	var claims jwt.MapClaims

	// Decode the token without verifying the signature
	_, _, err = jwt.NewParser().ParseUnverified(tokenResponse.AccessToken, &claims)
	if err != nil {
		c.logger.Error("error parsing token", "error", err)
		return "", fmt.Errorf("error parsing token: %w", err)
	}

	exp, err := claims.GetExpirationTime()
	if err != nil {
		c.logger.Error("invalid token expiration")
		return "", fmt.Errorf("invalid token expiration")
	}

	c.logger.Info("successfully refreshed access token", "expiresAt", exp.Time)

	c.accessToken = tokenResponse.AccessToken
	c.tokenExpires = exp.Time

	return tokenResponse.AccessToken, nil
}

func (c *defaultRemoteClient) FetchMetadata(chain, dataset string) (*EcsDataset, error) {
	token, err := c.getAccessToken()
	if err != nil {
		c.logger.Error("failed to get access token", "error", err)
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}

	c.logger.Debug("fetching metadata", "chain", chain, "dataset", dataset)

	apiURL := fmt.Sprintf("%s/api/ecs/%s/dataset/%s", c.baseURL, chain, dataset)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		c.logger.Error("error creating request", "error", err)
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Error("error making request", "error", err)
		return nil, fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.logger.Error("unexpected status code for metadata request",
			"url", apiURL,
			"statusCode", resp.StatusCode,
		)
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var metadata EcsDataset
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		c.logger.Error("error decoding response", "error", err)
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	return &metadata, nil
}

func (c *defaultRemoteClient) DownloadFile(ctx context.Context, url string, dest string) error {
	c.logger.Debug("downloading file", "url", url, "destination", dest)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		c.logger.Error("failed to create download request", "error", err)
		return fmt.Errorf("error creating request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Error("error downloading file", "error", err)
		return fmt.Errorf("error downloading file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.logger.Error("unexpected status code from download",
			"statusCode", resp.StatusCode,
		)
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	tmpFile, err := os.CreateTemp(filepath.Dir(dest), "*.tmp")
	if err != nil {
		c.logger.Error("error creating temp file", "error", err)
		return fmt.Errorf("error creating temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		c.logger.Error("error writing to temp file", "error", err)
		return fmt.Errorf("error writing to temp file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		c.logger.Error("error closing temp file", "error", err)
		return fmt.Errorf("error closing temp file: %w", err)
	}

	return os.Rename(tmpPath, dest)
}
