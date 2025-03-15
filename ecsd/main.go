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
)

type Response struct {
	Query   string `json:"query"`
	InSet   bool   `json:"in_set"`
	Message string `json:"message"`
}

type BatchCheckRequest struct {
	Addresses []string `json:"addresses"`
}

type BatchCheckResponse struct {
	Found         []string `json:"found"`
	NotFound      []string `json:"notfound"`
	FoundCount    int      `json:"found_count"`
	NotFoundCount int      `json:"notfound_count"`
}

type UpdateRequest struct {
	URL string `json:"url"`
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

	addressHandler := &address.EVMAddressHandler{}
	filter, lasterror = store.NewBloomFilterStoreFromFile(*filename, addressHandler, options...)

	if lasterror != nil {
		logger.Fatalf("Failed to load Bloom filter: %v", lasterror)
	}

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
	r.Handle("/update", rateLimitMiddleware(http.HandlerFunc(updateHandler))).Methods("POST")
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Inspect the Bloom filter
func inspectHandler(w http.ResponseWriter, r *http.Request) {
	stats := filter.GetStats()

	// Get file info for last modification time
	fileInfo, err := os.Stat("bloomfilter.gob")
	lastUpdate := ""
	if err == nil {
		lastUpdate = fileInfo.ModTime().Format(time.RFC3339)
	}

	response := struct {
		Stats      store.BloomStats `json:"stats"`
		LastUpdate string           `json:"last_update"`
		Error      string           `json:"error,omitempty"`
	}{
		Stats:      stats,
		LastUpdate: lastUpdate,
	}

	if err != nil {
		response.Error = err.Error()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Update the Bloom filter from a remote URL specified in baseURL
// reload the Bloom filter from the file downloaded from baseURL
// reload it safely using a mutex
// ensure the reload is done before replacing the filter variable
// run filter stats and update the stats in the response
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

	// Clear any previous errors
	lasterror = nil

	// Get the stats after successful reload
	stats := filter.GetStats()

	// Prepare response
	response := struct {
		Status  string           `json:"status"`
		Message string           `json:"message"`
		Stats   store.BloomStats `json:"stats"`
	}{
		Status:  "success",
		Message: "Bloom filter updated successfully",
		Stats:   stats,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Health check endpoint
func healthHandler(w http.ResponseWriter, r *http.Request) {
	response := struct {
		Status  string `json:"status"`
		Message string `json:"message,omitempty"`
		Filter  string `json:"filter,omitempty"`
	}{
		Status: "ok",
	}

	// Check if filter is nil or there's a previous error
	if filter == nil {
		response.Status = "error"
		response.Message = "Bloom filter not loaded"
		w.WriteHeader(http.StatusServiceUnavailable)
	} else if lasterror != nil {
		response.Status = "error"
		response.Message = lasterror.Error()
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		// Filter is loaded, add stats
		stats := filter.GetStats()
		response.Filter = fmt.Sprintf("loaded (elements: %d, capacity: %d)",
			stats.N, stats.EstimatedCapacity)
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
