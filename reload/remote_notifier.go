package reload

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// RemoteClient defines the interface for all remote operations
type RemoteClient interface {
	// FetchMetadata retrieves the bloom filter metadata for the given chain and dataset
	FetchMetadata(chain, dataset string) (*EcsDataset, error)
	// DownloadFile downloads the file from the given URL to the destination path
	DownloadFile(ctx context.Context, url string, dest string) error
}

type RemoteNotifier struct {
	chain        string
	dataset      string
	localPath    string
	client       RemoteClient
	ticker       *time.Ticker
	lastModified time.Time
	mu           sync.Mutex
	done         chan struct{}
}

func NewRemoteNotifierWithClient(chain, dataset, localPath string, client RemoteClient, checkInterval time.Duration) *RemoteNotifier {
	return &RemoteNotifier{
		chain:     chain,
		dataset:   dataset,
		localPath: localPath,
		client:    client,
		ticker:    time.NewTicker(checkInterval),
		done:      make(chan struct{}),
	}
}

type EcsDataset struct {
	FileURL      string    `json:"fileUrl"`
	LastModified time.Time `json:"lastModified"`
	Checksum     string    `json:"checksum"`
}

func NewRemoteNotifier(chain, dataset, baseURL, clientID, clientSecret, localPath string, checkInterval time.Duration) *RemoteNotifier {
	return &RemoteNotifier{
		chain:     chain,
		dataset:   dataset,
		client:    NewRemoteClient(baseURL, clientID, clientSecret),
		localPath: localPath,
		ticker:    time.NewTicker(checkInterval),
		done:      make(chan struct{}),
	}
}

func (n *RemoteNotifier) WatchForChange(ctx context.Context, onReload func(file string) error) error {
	// Initial check
	if err := n.checkAndNotify(ctx, onReload); err != nil {
		return fmt.Errorf("initial check failed: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-n.done:
			return nil
		case <-n.ticker.C:
			if err := n.checkAndNotify(ctx, onReload); err != nil {
				// Log error but continue watching
				fmt.Printf("Error checking for updates: %v\n", err)
			}
		}
	}
}

func (n *RemoteNotifier) checkAndNotify(ctx context.Context, onReload func(file string) error) error {
	metadata, err := n.client.FetchMetadata(n.chain, n.dataset)
	if err != nil {
		return fmt.Errorf("failed to fetch metadata: %w", err)
	}

	n.mu.Lock()
	needsUpdate := metadata.LastModified.After(n.lastModified)
	n.mu.Unlock()

	if needsUpdate {
		if err := n.client.DownloadFile(ctx, metadata.FileURL, n.localPath); err != nil {
			return fmt.Errorf("download failed: %w", err)
		}

		if err := onReload(n.localPath); err != nil {
			return fmt.Errorf("reload failed: %w", err)
		}

		n.mu.Lock()
		n.lastModified = metadata.LastModified
		n.mu.Unlock()
	}

	return nil
}

func (n *RemoteNotifier) Close() error {
	n.ticker.Stop()
	close(n.done)
	return nil
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
}

func NewRemoteClient(baseURL, clientID, clientSecret string) RemoteClient {
	return &defaultRemoteClient{
		baseURL:      baseURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		mu:           sync.RWMutex{},
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

	tokenURL := fmt.Sprintf("%s/oauth/token", c.baseURL)

	payload := map[string]string{
		"client_id":     c.clientID,
		"client_secret": c.clientSecret,
		"audience":      "svc.cipherowl.ai",
		"grant_type":    "client_credentials",
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", tokenURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return "", fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var tokenResponse TokenResponse

	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return "", fmt.Errorf("error decoding response: %w", err)
	}

	var claims jwt.MapClaims

	// Decode the token without verifying the signature
	_, _, err = jwt.NewParser().ParseUnverified(tokenResponse.AccessToken, &claims)
	if err != nil {
		return "", fmt.Errorf("error parsing token: %w", err)
	}

	exp, err := claims.GetExpirationTime()
	if err != nil {
		return "", fmt.Errorf("invalid token expiration")
	}

	c.accessToken = tokenResponse.AccessToken
	c.tokenExpires = exp.Time

	return tokenResponse.AccessToken, nil
}

func (c *defaultRemoteClient) FetchMetadata(chain, dataset string) (*EcsDataset, error) {
	token, err := c.getAccessToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}

	apiURL := fmt.Sprintf("%s/api/ecs/%s/dataset/%s", c.baseURL, chain, dataset)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var metadata EcsDataset
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	return &metadata, nil
}

func (c *defaultRemoteClient) DownloadFile(ctx context.Context, url string, dest string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("error downloading file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	tmpFile, err := os.CreateTemp(filepath.Dir(dest), "*.tmp")
	if err != nil {
		return fmt.Errorf("error creating temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		return fmt.Errorf("error writing to temp file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("error closing temp file: %w", err)
	}

	return os.Rename(tmpPath, dest)
}
