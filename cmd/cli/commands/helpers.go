package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/cipherowl-ai/addressdb/address"
	"github.com/cipherowl-ai/addressdb/securedata"
	"github.com/cipherowl-ai/addressdb/store"
)

const (
	tokenEndpoint = "/oauth/token"
	prodBaseURL   = "svc.cipherowl.ai"
	devBaseURL    = "svc.dev.cipherowl.ai"
)

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
}

// configurePGPHandler sets up the OpenPGPSecureHandler based on provided flags.
func configurePGPHandler() ([]store.Option, error) {
	pgpOptions := []securedata.Option{}
	if privateKeyFile != "" {
		pgpOptions = append(pgpOptions, securedata.WithPrivateKeyPath(privateKeyFile, privateKeyPassphrase))
	}
	if publicKeyFile != "" {
		pgpOptions = append(pgpOptions, securedata.WithPublicKeyPath(publicKeyFile))
	}

	var options []store.Option
	if len(pgpOptions) > 0 {
		pgpHandler, err := securedata.NewPGPSecureHandler(pgpOptions...)
		if err != nil {
			return nil, fmt.Errorf("error creating PGP handler: %w", err)
		}
		options = append(options, store.WithSecureDataHandler(pgpHandler))
	}

	return options, nil
}

// loadBloomFilter initializes the Bloom filter store with optional PGP handler.
func loadBloomFilter(filename string) (*store.BloomFilterStore, error) {
	options, err := configurePGPHandler()
	if err != nil {
		return nil, err
	}

	addressHandler := &address.EVMAddressHandler{}
	filter, err := store.NewBloomFilterStoreFromFile(filename, addressHandler, options...)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}

	return filter, nil
}

func checkAuth(clientID, clientSecret, env string) error {
	baseURL := prodBaseURL
	if env == "dev" {
		baseURL = devBaseURL
	}

	payload := map[string]string{
		"client_id":     clientID,
		"client_secret": clientSecret,
		"audience":      baseURL,
		"grant_type":    "client_credentials",
		"force_refresh": "true",
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %v", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authentication failed with status code: %d", resp.StatusCode)
	}

	var tokenResp tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("failed to decode response: %v", err)
	}

	if !strings.Contains(tokenResp.Scope, "bloomfilter:read") {
		return fmt.Errorf("insufficient permissions: bloomfilter:read permission required")
	}

	return nil
}
