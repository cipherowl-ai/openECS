package reload

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func generateTestToken(expiresIn time.Duration) string {
	claims := jwt.MapClaims{
		"exp": time.Now().Add(expiresIn).Unix(),
		"iat": time.Now().Unix(),
		"sub": "test-client",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, _ := token.SignedString([]byte("test-secret"))
	return signedToken
}

func TestDefaultRemoteClient_FetchMetadata(t *testing.T) {
	tests := []struct {
		name           string
		serverHandler  http.HandlerFunc
		expectedError  bool
		expectedURL    string
		checkHeaders   bool
		expectedChain  string
		expectedFileID string
	}{
		{
			name: "successful fetch",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/oauth/token":
					token := TokenResponse{
						AccessToken: generateTestToken(time.Hour),
					}
					w.Header().Set("Content-Type", "application/json")
					if err := json.NewEncoder(w).Encode(token); err != nil {
						t.Errorf("failed to encode token: %v", err)
					}
				case "/api/ecs/ethereum/dataset/test-file":
					// Check auth header exists
					if r.Header.Get("Authorization") == "" {
						w.WriteHeader(http.StatusUnauthorized)
						return
					}

					w.Header().Set("Content-Type", "application/json")
					metadata := EcsDataset{
						FileURL:      "https://example.com/test.bloom",
						LastModified: time.Now().Unix(),
						Checksum:     "test-checksum",
					}
					if err := json.NewEncoder(w).Encode(metadata); err != nil {
						t.Errorf("failed to encode metadata: %v", err)
					}
				default:
					t.Logf("unexpected path: %s", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			},
			expectedError:  false,
			expectedURL:    "https://example.com/test.bloom",
			checkHeaders:   true,
			expectedChain:  "ethereum",
			expectedFileID: "test-file",
		},
		{
			name: "expired token refresh",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/oauth/token":
					// First token is expired
					if r.Header.Get("Authorization") == "" {
						token := TokenResponse{
							AccessToken: generateTestToken(-time.Hour), // expired token
						}
						json.NewEncoder(w).Encode(token)
					} else {
						// Refresh token is valid
						token := TokenResponse{
							AccessToken: generateTestToken(time.Hour),
						}
						json.NewEncoder(w).Encode(token)
					}
				case "/api/ecs/ethereum/dataset/test-file":
					metadata := EcsDataset{
						FileURL:      "https://example.com/test.bloom",
						LastModified: time.Now().Unix(),
						Checksum:     "test-checksum",
					}
					json.NewEncoder(w).Encode(metadata)
				}
			},
			expectedError:  false,
			expectedURL:    "https://example.com/test.bloom",
			expectedChain:  "ethereum",
			expectedFileID: "test-file",
		},
		{
			name: "token fetch fails",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/oauth/token" {
					w.WriteHeader(http.StatusUnauthorized)
				}
			},
			expectedError: true,
		},
		{
			name: "metadata fetch fails",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/oauth/token":
					token := TokenResponse{
						AccessToken: "test-token",
					}
					json.NewEncoder(w).Encode(token)
				case "/api/ecs/ethereum/dataset/test-file":
					w.WriteHeader(http.StatusNotFound)
				}
			},
			expectedError: true,
		},
		{
			name: "invalid json response",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/oauth/token":
					token := TokenResponse{
						AccessToken: "test-token",
					}
					json.NewEncoder(w).Encode(token)
				case "/api/ecs/ethereum/dataset/test-file":
					w.Write([]byte("invalid json"))
				}
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.serverHandler)
			defer server.Close()

			client := NewRemoteClient(server.URL, "test-client", "test-secret", slog.Default())
			metadata, err := client.FetchMetadata(tt.expectedChain, tt.expectedFileID)

			if tt.expectedError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if metadata == nil {
				t.Error("expected metadata not to be nil")
				return
			}

			if metadata.FileURL != tt.expectedURL {
				t.Errorf("expected URL %s, got %s", tt.expectedURL, metadata.FileURL)
			}
		})
	}
}

func TestDefaultRemoteClient_DownloadFile(t *testing.T) {
	tests := []struct {
		name          string
		serverHandler http.HandlerFunc
		expectedError bool
	}{
		{
			name: "successful download",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/oauth/token":
					token := TokenResponse{
						AccessToken: generateTestToken(time.Hour),
					}
					json.NewEncoder(w).Encode(token)
				default:
					w.Write([]byte("test content"))
				}
			},
			expectedError: false,
		},
		{
			name: "server error",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/oauth/token":
					token := TokenResponse{
						AccessToken: generateTestToken(time.Hour),
					}
					json.NewEncoder(w).Encode(token)
				default:
					w.WriteHeader(http.StatusInternalServerError)
				}
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.serverHandler)
			defer server.Close()

			client := NewRemoteClient(server.URL, "test-client", "test-secret", slog.Default())

			// Create a temporary file for testing
			tmpfile, err := os.CreateTemp("", "test-download-*")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(tmpfile.Name())
			tmpfile.Close()

			err = client.DownloadFile(context.Background(), server.URL, tmpfile.Name())

			if tt.expectedError && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.expectedError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestDefaultRemoteClient_TokenRefresh(t *testing.T) {
	tokenCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			tokenCount++
			var token TokenResponse
			if tokenCount == 1 {
				// First token expires in 1 second
				token = TokenResponse{
					AccessToken: generateTestToken(time.Second),
				}
			} else {
				// Subsequent tokens are valid for longer
				token = TokenResponse{
					AccessToken: generateTestToken(time.Hour),
				}
			}
			json.NewEncoder(w).Encode(token)
		case "/api/ecs/ethereum/dataset/test-file":
			metadata := EcsDataset{
				FileURL:      "https://example.com/test.bloom",
				LastModified: time.Now().Unix(),
				Checksum:     "test-checksum",
			}
			json.NewEncoder(w).Encode(metadata)
		}
	}))
	defer server.Close()

	client := NewRemoteClient(server.URL, "test-client", "test-secret", slog.Default())

	// First request should get a token
	_, err := client.FetchMetadata("ethereum", "test-file")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Wait for token to expire
	time.Sleep(2 * time.Second)

	// Second request should refresh the token
	_, err = client.FetchMetadata("ethereum", "test-file")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if tokenCount != 2 {
		t.Errorf("expected 2 token requests, got %d", tokenCount)
	}
}

func TestDefaultRemoteClient_Concurrent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			token := TokenResponse{
				AccessToken: generateTestToken(time.Hour),
			}
			json.NewEncoder(w).Encode(token)
		case "/api/ecs/ethereum/dataset/test-file":
			if r.Header.Get("Authorization") == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			metadata := EcsDataset{
				FileURL:      "https://example.com/test.bloom",
				LastModified: time.Now().Unix(),
				Checksum:     "test-checksum",
			}
			json.NewEncoder(w).Encode(metadata)
		}
	}))
	defer server.Close()

	client := NewRemoteClient(server.URL, "test-client", "test-secret", slog.Default())

	// Run concurrent requests
	concurrency := 10
	errs := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		go func() {
			_, err := client.FetchMetadata("ethereum", "test-file")
			errs <- err
		}()
	}

	// Check all results
	for i := 0; i < concurrency; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent request failed: %v", err)
		}
	}
}
