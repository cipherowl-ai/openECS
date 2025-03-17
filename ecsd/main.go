package main

/**
 * Edge compliance service for Bloom filter
 * Provides HTTP endpoints to check addresses against a Bloom filter
 */
import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/cipherowl-ai/addressdb/address"
	"github.com/cipherowl-ai/addressdb/reload"
	"github.com/cipherowl-ai/addressdb/securedata"
	"github.com/cipherowl-ai/addressdb/store"

	"strconv"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"golang.org/x/time/rate"
)

var (
	filter               *store.BloomFilterStore
	logger               = log.New(os.Stdout, "BloomServer: ", log.LstdFlags)
	lasterror            error
	ratelimit            int
	burst                int
	privateKeyFile       string
	publicKeyFile        string
	privateKeyPassphrase string
	clientID             string
	clientSecret         string
	baseURL              string
	environment          string
	updateLimiter        = rate.NewLimiter(rate.Limit(0.2), 1) // 1 request every 5 seconds for updates
	lastFilterLoadTime   time.Time                             // Tracks when filter was last successfully loaded
)

type Response struct {
	Query        string            `json:"query"`
	InSet        bool              `json:"in_set"`
	Message      string            `json:"message"`
	Explanations map[string]string `json:"__llm_explanations__data_dictionary__,omitempty"`
}

type BatchCheckRequest struct {
	Addresses []string `json:"addresses"`
}

type BatchCheckResponse struct {
	Found         []string          `json:"found"`
	NotFound      []string          `json:"notfound"`
	FoundCount    int               `json:"found_count"`
	NotFoundCount int               `json:"notfound_count"`
	Explanations  map[string]string `json:"__llm_explanations__data_dictionary__,omitempty"`
}

type UpdateRequest struct {
	URL string `json:"url"`
}

// The mapping of valid header values for efficient lookup
var llmCallerValues = map[string]bool{
	"on":   true,
	"true": true,
	"1":    true,
	"yes":  true,
	"y":    true,
}

// shouldIncludeExplanations checks if explanations for LLM bots should be included in the response
// Using a map lookup with case-insensitive comparison for maximum compatibility and O(1) time complexity
func shouldIncludeExplanations(r *http.Request) bool {
	headerValue := strings.ToLower(r.Header.Get("__llm_bot_caller__"))
	return llmCallerValues[headerValue]
}

func main() {
	// Load .env file if it exists
	godotenv.Load()

	// Load environment variables with defaults
	clientID = getEnv("CO_CLIENT_ID", "")
	clientSecret = getEnv("CO_CLIENT_SECRET", "")
	baseURL = getEnv("CO_BASE_URL", "svc.cipherowl.ai")
	environment = getEnv("CO_ENV", "prod")
	privateKeyPassphrase = getEnv("KEY_PASSPHRASE", "")

	// Command line flags
	filename := flag.String("f", "bloomfilter.gob", "Path to the .gob file containing the Bloom filter")
	port := flag.Int("p", 8080, "Port to listen on")
	ratelimit_v := flag.Int("r", 20, "Ratelimit")
	burst_v := flag.Int("b", 5, "Burst")
	flag.StringVar(&privateKeyFile, "private-key-file", "", "Path to the private key file (optional)")
	flag.StringVar(&publicKeyFile, "public-key-file", "", "Path to the public key file (optional)")
	flag.Parse()

	// Use the values
	ratelimit = *ratelimit_v
	burst = *burst_v

	logger.Printf("Starting with configuration: port=%d, ratelimit=%d, burst=%d, env=%s", *port, ratelimit, burst, environment)

	// Configure PGP handler if keys are provided
	var options []store.Option
	if privateKeyFile != "" || publicKeyFile != "" {
		pgpOptions := []securedata.Option{}
		if privateKeyFile != "" {
			pgpOptions = append(pgpOptions, securedata.WithPrivateKeyPath(privateKeyFile, privateKeyPassphrase))
		}
		if publicKeyFile != "" {
			pgpOptions = append(pgpOptions, securedata.WithPublicKeyPath(publicKeyFile))
		}

		pgpHandler, err := securedata.NewPGPSecureHandler(pgpOptions...)
		if err != nil {
			logger.Fatalf("Failed to create PGP handler: %v", err)
		}
		options = append(options, store.WithSecureDataHandler(pgpHandler))
	}

	// Create address handler
	addressHandler := &address.EVMAddressHandler{}

	// First create an empty filter
	var err error
	filter, err = store.NewBloomFilterStoreFromFile(*filename, addressHandler, options...)

	// Record initial load time
	lastFilterLoadTime = time.Now().UTC()

	// Create a file watcher notifier.
	notifier, err := reload.NewFileWatcherNotifier(*filename, 2*time.Second)
	if err != nil {
		log.Fatalf("Error creating file watcher notifier: %v", err)
	}

	// Create the ReloadManager with the notifier.
	manager := reload.NewReloadManager(filter, notifier)
	if err := manager.Start(context.Background()); err != nil {
		log.Fatalf("Error starting Bloom filter manager: %v", err)
	}
	defer manager.Stop()

	r := mux.NewRouter()
	r.Use(loggingMiddleware)

	// Define routes as per README
	r.Handle("/check", rateLimitMiddleware(http.HandlerFunc(checkHandler))).Methods("GET")
	r.Handle("/batch-check", rateLimitMiddleware(http.HandlerFunc(batchCheckHandler))).Methods("POST")
	r.Handle("/inspect", rateLimitMiddleware(http.HandlerFunc(inspectHandler))).Methods("GET")
	r.Handle("/update", updateRateLimitMiddleware(http.HandlerFunc(updateHandler))).Methods("PATCH") //limit patch requests, so backend won't get overwhelmed
	r.Handle("/health", http.HandlerFunc(healthHandler)).Methods("GET")

	srv := &http.Server{
		Addr:         ":" + strconv.Itoa(*port),
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		logger.Printf("Starting server on port %d", *port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Could not listen on %d: %v\n", *port, err)
		}
	}()

	gracefulShutdown(srv)
}

// Helper function to get environment variables with defaults
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// Check if an address is in the Bloom filter
func checkHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("address")
	if query == "" {
		http.Error(w, `{"error": "Missing 'address' parameter"}`, http.StatusBadRequest)
		return
	}

	found, err := filter.CheckAddress(query)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Error checking address: %v"}`, err), http.StatusInternalServerError)
		return
	}

	response := Response{
		Query:   query,
		InSet:   found,
		Message: "",
	}

	// Only include explanations if the bot caller header is present
	if shouldIncludeExplanations(r) {
		response.Explanations = map[string]string{
			"query":   "Queried address",
			"in_set":  "Address presence in Bloom filter. May have false positives but never false negatives",
			"message": "Error or additional info",
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Batch check addresses in the Bloom filter
func batchCheckHandler(w http.ResponseWriter, r *http.Request) {
	var requestBody BatchCheckRequest

	// Parse from request body
	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		http.Error(w, `{"error": "Invalid JSON body"}`, http.StatusBadRequest)
		return
	}

	// Check if the addresses list is empty
	if len(requestBody.Addresses) == 0 {
		http.Error(w, `{"error": "Empty addresses list"}`, http.StatusBadRequest)
		return
	}

	// Check that the addresses list is not too long
	if len(requestBody.Addresses) > 100 {
		http.Error(w, `{"error": "Too many addresses, maximum is 100"}`, http.StatusBadRequest)
		return
	}

	// Check each address against the Bloom filter
	found := make([]string, 0)
	notFound := make([]string, 0)

	for _, address := range requestBody.Addresses {
		if ok, err := filter.CheckAddress(address); ok && err == nil {
			found = append(found, address)
		} else {
			notFound = append(notFound, address)
		}
	}

	response := BatchCheckResponse{
		Found:         found,
		NotFound:      notFound,
		FoundCount:    len(found),
		NotFoundCount: len(notFound),
	}

	// Only include explanations if the bot caller header is present
	if shouldIncludeExplanations(r) {
		response.Explanations = map[string]string{
			"found":          "Addresses found in filter",
			"notfound":       "Addresses not found in filter",
			"found_count":    "Count of found addresses",
			"notfound_count": "Count of addresses not found",
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Inspect the Bloom filter
func inspectHandler(w http.ResponseWriter, r *http.Request) {
	stats := filter.GetStats()

	lastUpdate := lastFilterLoadTime.Format(time.RFC3339)

	response := struct {
		Stats        store.BloomStats  `json:"stats"`
		LastUpdate   string            `json:"last_update"`
		Error        string            `json:"error,omitempty"`
		Explanations map[string]string `json:"__llm_explanations__data_dictionary__,omitempty"`
	}{
		Stats:      stats,
		LastUpdate: lastUpdate,
	}

	// Only include explanations if the bot caller header is present
	if shouldIncludeExplanations(r) {
		response.Explanations = map[string]string{
			"k":                   "Number of hash functions",
			"m":                   "Bit array size",
			"n":                   "Elements count",
			"estimated_capacity":  "Maximum capacity before exceeding false positive threshold",
			"last_update":         "Last reload timestamp (UTC)",
			"false_positive_rate": "Current false positive probability (should be less than configured threshold)",
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Update the Bloom filter from a remote URL specified in baseURL
// reload the Bloom filter from the file downloaded from baseURL
// reload it safely using a mutex
// ensure the reload is done before replacing the filter variable
// run filter stats and update the stats in the response
// TODO:
// 1. test with CO backend with real data
// 2. test with failure cases
func updateHandler(w http.ResponseWriter, r *http.Request) {
	// Create HTTP client
	client := &http.Client{
		Timeout: 60 * time.Second,
	}

	// Construct URL from baseURL
	url := fmt.Sprintf("https://%s/api/bloomfilter", baseURL)

	// Log the operation
	logger.Printf("Downloading Bloom filter from URL: %s", url)

	// Create request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Failed to create HTTP request: %v"}`, err), http.StatusInternalServerError)
		return
	}

	// Add authentication if needed
	if clientID != "" && clientSecret != "" {
		req.SetBasicAuth(clientID, clientSecret)
	}

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Failed to download file: %v"}`, err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(w, fmt.Sprintf(`{"error": "Failed to download file, status: %s"}`, resp.Status), http.StatusInternalServerError)
		return
	}

	// Create temporary file
	tempFile, err := os.CreateTemp("", "bloomfilter-*.gob")
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Failed to create temporary file: %v"}`, err), http.StatusInternalServerError)
		return
	}
	tempFilePath := tempFile.Name()
	defer os.Remove(tempFilePath) // Clean up temp file

	// Copy downloaded data to temp file
	_, err = io.Copy(tempFile, resp.Body)
	tempFile.Close() // Close the file before loading it
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Failed to save downloaded file: %v"}`, err), http.StatusInternalServerError)
		return
	}

	// Load the new filter data directly into the existing filter
	err = filter.LoadFromFile(tempFilePath)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Failed to load new Bloom filter: %v"}`, err), http.StatusInternalServerError)
		return
	}

	// Update the last load time
	lastFilterLoadTime = time.Now().UTC()

	// Clear any previous errors
	lasterror = nil

	// Get the stats after successful reload
	stats := filter.GetStats()

	// Prepare response
	response := struct {
		Status       string            `json:"status"`
		Message      string            `json:"message"`
		Stats        store.BloomStats  `json:"stats"`
		Explanations map[string]string `json:"__llm_explanations__data_dictionary__,omitempty"`
	}{
		Status:  "success",
		Message: "Bloom filter updated successfully",
		Stats:   stats,
	}

	// Only include explanations if the bot caller header is present
	if shouldIncludeExplanations(r) {
		response.Explanations = map[string]string{
			"status":                    "Operation status",
			"message":                   "Status description",
			"stats.k":                   "Hash function count",
			"stats.m":                   "Bit array size",
			"stats.n":                   "Element count",
			"stats.estimated_capacity":  "Maximum capacity estimate",
			"stats.false_positive_rate": "Current false positive probability",
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Health check endpoint
func healthHandler(w http.ResponseWriter, r *http.Request) {
	response := struct {
		Status       string            `json:"status"`
		Message      string            `json:"message,omitempty"`
		Filter       string            `json:"filter,omitempty"`
		Explanations map[string]string `json:"__llm_explanations__data_dictionary__,omitempty"`
	}{
		Status: "ok",
	}

	// Check if filter is nil or there's a previous error
	if filter == nil {
		response.Status = "error"
		response.Message = "Bloom filter not loaded"
	} else if lasterror != nil {
		response.Status = "error"
		response.Message = lasterror.Error()
	} else {
		// Filter is loaded, add stats
		stats := filter.GetStats()
		response.Filter = fmt.Sprintf("loaded (elements: %d, capacity: %d)",
			stats.N, stats.EstimatedCapacity)
	}

	// Set appropriate HTTP status code based on response status
	if response.Status != "ok" {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	// Only include explanations if the bot caller header is present
	if shouldIncludeExplanations(r) {
		response.Explanations = map[string]string{
			"status":  "Service status (ok/error)",
			"message": "Error details",
			"filter":  "Bloom filter stats summary",
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		logger.Printf(
			"%s %s %s %s",
			r.Method,
			r.RequestURI,
			r.RemoteAddr,
			time.Since(start),
		)
	})
}

func rateLimitMiddleware(next http.Handler) http.Handler {
	limiter := rate.NewLimiter(rate.Limit(ratelimit), burst)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func updateRateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !updateLimiter.Allow() {
			http.Error(w, "Too many update requests, limit is 1 per second", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func gracefulShutdown(srv *http.Server) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	srv.Shutdown(ctx)
	logger.Println("shutting down")
	os.Exit(0)
}
