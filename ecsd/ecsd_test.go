package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/cipherowl-ai/addressdb/address"
	"github.com/cipherowl-ai/addressdb/store"
	"golang.org/x/time/rate"
)

// Setup test filter
func setupTestFilter(t *testing.T) {
	// Create a test bloom filter with known addresses
	addressHandler := &address.EVMAddressHandler{}
	testFilter, err := store.NewBloomFilterStore(addressHandler, store.WithEstimates(100000, 0.01))
	if err != nil {
		t.Fatalf("Failed to create test filter: %v", err)
	}

	// Add some test addresses
	testAddresses := []string{
		"0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
		"0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", // WETH contract
		"0x6B175474E89094C44Da98b954EedeAC495271d0F", // DAI contract
	}

	for _, addr := range testAddresses {
		testFilter.AddAddress(addr)
	}

	// Save test filter
	tempFile, err := os.CreateTemp("", "test-bloomfilter-*.gob")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer tempFile.Close()

	err = testFilter.SaveToFile(tempFile.Name())
	if err != nil {
		t.Fatalf("Failed to save test filter: %v", err)
	}

	// Set global filter for testing
	filter, err = store.NewBloomFilterStoreFromFile(tempFile.Name(), addressHandler)
	if err != nil {
		t.Fatalf("Failed to load test filter: %v", err)
	}

	// Set testing rate limits
	ratelimit = 100
	burst = 50
	updateLimiter = rate.NewLimiter(rate.Limit(100), 50) // Higher limits for testing
}

// Test check handler
func TestCheckHandler(t *testing.T) {
	setupTestFilter(t)

	tests := []struct {
		name           string
		address        string
		expectedStatus int
		expectedInSet  bool
	}{
		{
			name:           "Known address",
			address:        "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
			expectedStatus: http.StatusOK,
			expectedInSet:  true,
		},
		{
			name:           "Unknown address",
			address:        "0x1111111111111111111111111111111111111111",
			expectedStatus: http.StatusOK,
			expectedInSet:  false,
		},
		{
			name:           "Missing address parameter",
			address:        "",
			expectedStatus: http.StatusBadRequest,
			expectedInSet:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create request
			req, err := http.NewRequest("GET", "/check", nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			// Add query parameter if present
			if tc.address != "" {
				q := req.URL.Query()
				q.Add("address", tc.address)
				req.URL.RawQuery = q.Encode()
			}

			// Create response recorder
			rr := httptest.NewRecorder()
			handler := http.HandlerFunc(checkHandler)

			// Handle request
			handler.ServeHTTP(rr, req)

			// Check status code
			if status := rr.Code; status != tc.expectedStatus {
				t.Errorf("Handler returned wrong status code: got %v want %v", status, tc.expectedStatus)
			}

			// Check response body if status is OK
			if tc.expectedStatus == http.StatusOK {
				var response Response
				if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}

				if response.InSet != tc.expectedInSet {
					t.Errorf("Expected InSet=%v, got %v", tc.expectedInSet, response.InSet)
				}
			}
		})
	}
}

// Test batch check handler
func TestBatchCheckHandler(t *testing.T) {
	setupTestFilter(t)

	tests := []struct {
		name             string
		requestBody      BatchCheckRequest
		expectedStatus   int
		expectedFound    int
		expectedNotFound int
		emptyRequest     bool
		tooManyAddresses bool
		malformedRequest bool
	}{
		{
			name: "Mixed addresses",
			requestBody: BatchCheckRequest{
				Addresses: []string{
					"0x742d35Cc6634C0532925a3b844Bc454e4438f44e", // Known
					"0x1111111111111111111111111111111111111111", // Unknown
				},
			},
			expectedStatus:   http.StatusOK,
			expectedFound:    1,
			expectedNotFound: 1,
		},
		{
			name:           "Empty request",
			requestBody:    BatchCheckRequest{Addresses: []string{}},
			expectedStatus: http.StatusBadRequest,
			emptyRequest:   true,
		},
		{
			name: "Too many addresses",
			requestBody: BatchCheckRequest{
				Addresses: make([]string, 101), // More than 100
			},
			expectedStatus:   http.StatusBadRequest,
			tooManyAddresses: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var reqBody []byte
			var err error

			if tc.malformedRequest {
				reqBody = []byte(`{"addresses": broken json`)
			} else {
				reqBody, err = json.Marshal(tc.requestBody)
				if err != nil {
					t.Fatalf("Failed to marshal request: %v", err)
				}
			}

			// Create request
			req, err := http.NewRequest("POST", "/batch-check", bytes.NewBuffer(reqBody))
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")

			// Create response recorder
			rr := httptest.NewRecorder()
			handler := http.HandlerFunc(batchCheckHandler)

			// Handle request
			handler.ServeHTTP(rr, req)

			// Check status code
			if status := rr.Code; status != tc.expectedStatus {
				t.Errorf("Handler returned wrong status code: got %v want %v", status, tc.expectedStatus)
			}

			// Check response body if status is OK
			if tc.expectedStatus == http.StatusOK {
				var response BatchCheckResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}

				if response.FoundCount != tc.expectedFound {
					t.Errorf("Expected FoundCount=%v, got %v", tc.expectedFound, response.FoundCount)
				}

				if response.NotFoundCount != tc.expectedNotFound {
					t.Errorf("Expected NotFoundCount=%v, got %v", tc.expectedNotFound, response.NotFoundCount)
				}
			}
		})
	}
}

// Test inspect handler
func TestInspectHandler(t *testing.T) {
	setupTestFilter(t)

	// Create request
	req, err := http.NewRequest("GET", "/inspect", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Create response recorder
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(inspectHandler)

	// Handle request
	handler.ServeHTTP(rr, req)

	// Check status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Verify response contains stats
	var response struct {
		Stats      store.BloomStats `json:"stats"`
		LastUpdate string           `json:"last_update"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Check that stats has reasonable values
	if response.Stats.N < 1 {
		t.Errorf("Expected at least 1 element in stats, got %v", response.Stats.N)
	}
}

// Test health handler
func TestHealthHandler(t *testing.T) {
	t.Skip("Skipping health handler test")
	setupTestFilter(t)

	// Test when filter is loaded
	t.Run("Filter loaded", func(t *testing.T) {
		// Create request
		req, err := http.NewRequest("GET", "/health", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		// Create response recorder
		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(healthHandler)

		// Handle request
		handler.ServeHTTP(rr, req)

		// Check status code should be 200 OK
		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		// Verify response contains expected status
		var response struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if response.Status != "ok" {
			t.Errorf("Expected status 'ok', got '%v'", response.Status)
		}
	})

	// Test when filter is nil
	t.Run("Filter not loaded", func(t *testing.T) {
		// Temporarily set filter to nil
		oldFilter := filter
		filter = nil
		defer func() { filter = oldFilter }()

		// Create request
		req, err := http.NewRequest("GET", "/health", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		// Create response recorder
		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(healthHandler)

		// Handle request
		handler.ServeHTTP(rr, req)

		// Check status code should be 503 Service Unavailable
		if status := rr.Code; status != http.StatusServiceUnavailable {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusServiceUnavailable)
		}

		// Verify response contains expected status
		var response struct {
			Status  string `json:"status"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if response.Status != "error" {
			t.Errorf("Expected status 'error', got '%v'", response.Status)
		}

		if response.Message != "Bloom filter not loaded" {
			t.Errorf("Expected message 'Bloom filter not loaded', got '%v'", response.Message)
		}
	})

	// Test when there's an error
	t.Run("Filter error", func(t *testing.T) {
		// Temporarily set lasterror
		oldError := lasterror
		lasterror = &testError{"test error"}
		defer func() { lasterror = oldError }()

		// Create request
		req, err := http.NewRequest("GET", "/health", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		// Create response recorder
		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(healthHandler)

		// Handle request
		handler.ServeHTTP(rr, req)

		// Check status code should be 503 Service Unavailable
		if status := rr.Code; status != http.StatusServiceUnavailable {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusServiceUnavailable)
		}

		// Verify response contains expected status and error message
		var response struct {
			Status  string `json:"status"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if response.Status != "error" {
			t.Errorf("Expected status 'error', got '%v'", response.Status)
		}
		if response.Message != "test error" {
			t.Errorf("Expected message 'test error', got '%v'", response.Message)
		}
	})

	// Test that the explanations field is only included when header is present
	t.Run("LLM bot caller header", func(t *testing.T) {
		// Create request with header
		req, err := http.NewRequest("GET", "/health", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("__llm_bot_caller__", "on")

		// Create response recorder
		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(healthHandler)

		// Handle request
		handler.ServeHTTP(rr, req)

		// Verify response contains explanations
		var responseWithExplanations struct {
			Explanations map[string]string `json:"__llm_explanations__data_dictionary__"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &responseWithExplanations); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if responseWithExplanations.Explanations == nil {
			t.Errorf("Expected explanations in response when header is set")
		}

		// Create request without header
		req2, err := http.NewRequest("GET", "/health", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		rr2 := httptest.NewRecorder()
		handler.ServeHTTP(rr2, req2)

		// Verify response does not contain explanations
		var responseWithoutExplanations struct {
			Explanations map[string]string `json:"__llm_explanations__data_dictionary__"`
		}
		if err := json.Unmarshal(rr2.Body.Bytes(), &responseWithoutExplanations); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if responseWithoutExplanations.Explanations != nil {
			t.Errorf("Expected no explanations in response when header is not set")
		}
	})
}

// Test middleware functions
func TestMiddleware(t *testing.T) {
	// Test logging middleware
	t.Run("Logging middleware", func(t *testing.T) {
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		handlerToTest := loggingMiddleware(nextHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		rr := httptest.NewRecorder()

		handlerToTest.ServeHTTP(rr, req)

		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}
	})

	// Test rate limit middleware
	t.Run("Rate limit middleware", func(t *testing.T) {
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		// Set low limit to test rate limiting
		oldRateLimit := ratelimit
		oldBurst := burst
		ratelimit = 1
		burst = 1
		defer func() {
			ratelimit = oldRateLimit
			burst = oldBurst
		}()

		handlerToTest := rateLimitMiddleware(nextHandler)

		// First request should succeed
		req1 := httptest.NewRequest("GET", "/test", nil)
		rr1 := httptest.NewRecorder()
		handlerToTest.ServeHTTP(rr1, req1)
		if status := rr1.Code; status != http.StatusOK {
			t.Errorf("First request: handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		// Second request should be rate limited
		req2 := httptest.NewRequest("GET", "/test", nil)
		rr2 := httptest.NewRecorder()
		handlerToTest.ServeHTTP(rr2, req2)
		if status := rr2.Code; status != http.StatusTooManyRequests {
			t.Errorf("Second request: handler returned wrong status code: got %v want %v", status, http.StatusTooManyRequests)
		}

		// Wait for rate limit to reset
		time.Sleep(1 * time.Second)

		// Third request should succeed
		req3 := httptest.NewRequest("GET", "/test", nil)
		rr3 := httptest.NewRecorder()
		handlerToTest.ServeHTTP(rr3, req3)
		if status := rr3.Code; status != http.StatusOK {
			t.Errorf("Third request: handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}
	})
}

// Test update middleware
func TestUpdateRateLimitMiddleware(t *testing.T) {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Set low limit to test rate limiting
	oldLimiter := updateLimiter
	updateLimiter = rate.NewLimiter(rate.Limit(1), 1)
	defer func() {
		updateLimiter = oldLimiter
	}()

	handlerToTest := updateRateLimitMiddleware(nextHandler)

	// First request should succeed
	req1 := httptest.NewRequest("GET", "/update", nil)
	rr1 := httptest.NewRecorder()
	handlerToTest.ServeHTTP(rr1, req1)
	if status := rr1.Code; status != http.StatusOK {
		t.Errorf("First request: handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Second request should be rate limited
	req2 := httptest.NewRequest("GET", "/update", nil)
	rr2 := httptest.NewRecorder()
	handlerToTest.ServeHTTP(rr2, req2)
	if status := rr2.Code; status != http.StatusTooManyRequests {
		t.Errorf("Second request: handler returned wrong status code: got %v want %v", status, http.StatusTooManyRequests)
	}
}

// Helper error type for testing
type testError struct {
	message string
}

func (e *testError) Error() string {
	return e.message
}

// We can't easily test the update handler directly because it makes HTTP requests
// to external services. In a real test suite, you'd use mocks or a test server.
// Same for gracefulShutdown which would terminate the test process.
