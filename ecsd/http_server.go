package ecsd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cipherowl-ai/openECS/internal/config"
	"github.com/cipherowl-ai/openECS/store"
	"github.com/gorilla/mux"
	"golang.org/x/time/rate"
)

// The mapping of valid header values for efficient lookup
var llmCallerValues = map[string]bool{
	"on":   true,
	"true": true,
	"1":    true,
	"yes":  true,
	"y":    true,
}

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

type LoaderInfo interface {
	LastLoadTime() time.Time
}

// Introduce HTTPServer struct to hold references instead of global variables
type HTTPServer struct {
	filter  *store.BloomFilterStore
	reload  LoaderInfo
	logger  *slog.Logger
	httpSrv *http.Server
	config  *config.ServerConfig
}

// NewHTTPServer constructor that wires dependencies into the struct.
// You can adapt the arguments here to fit your usage (for instance, pass in a custom config if needed).
func NewHTTPServer(
	filter *store.BloomFilterStore,
	reload LoaderInfo,
	logger *slog.Logger,
	config *config.ServerConfig,
) *HTTPServer {
	return &HTTPServer{
		filter:  filter,
		reload:  reload,
		logger:  logger,
		httpSrv: nil,
		config:  config,
	}
}

// Refactor original healthHandler into a receiver method
func (hs *HTTPServer) healthHandler(w http.ResponseWriter, r *http.Request) {
	response := struct {
		Status       string            `json:"status"`
		Message      string            `json:"message,omitempty"`
		Filter       string            `json:"filter,omitempty"`
		Explanations map[string]string `json:"__llm_explanations__data_dictionary__,omitempty"`
	}{
		Status: "ok",
	}

	if hs.filter == nil || hs.reload.LastLoadTime().IsZero() {
		response.Status = "error"
		response.Message = "Bloom filter not loaded"
	} else {
		// Filter is loaded, add stats
		stats := hs.filter.GetStats()
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

// Check if an address is in the Bloom filter
func (hs *HTTPServer) checkHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("address")
	if query == "" {
		http.Error(w, `{"error": "Missing 'address' parameter"}`, http.StatusBadRequest)
		return
	}

	found, err := hs.filter.CheckAddress(query)
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
func (hs *HTTPServer) batchCheckHandler(w http.ResponseWriter, r *http.Request) {
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
		if ok, err := hs.filter.CheckAddress(address); ok && err == nil {
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
func (hs *HTTPServer) inspectHandler(w http.ResponseWriter, r *http.Request) {
	stats := hs.filter.GetStats()

	response := struct {
		Stats        store.BloomStats  `json:"stats"`
		LastUpdate   string            `json:"last_update"`
		Error        string            `json:"error,omitempty"`
		Explanations map[string]string `json:"__llm_explanations__data_dictionary__,omitempty"`
	}{
		Stats:      stats,
		LastUpdate: hs.reload.LastLoadTime().Format(time.RFC3339),
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

func (hs *HTTPServer) GracefulShutdown() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	hs.httpSrv.Shutdown(ctx)
	hs.logger.Info("shutting down")
	os.Exit(0)
}

// StartHTTPServer creates the HTTP server with routes and returns it.
func (hs *HTTPServer) StartHTTPServer(port int) {

	r := mux.NewRouter()
	r.Use(hs.loggingMiddleware)

	r.Handle("/check", rateLimitMiddleware(http.HandlerFunc(hs.checkHandler), hs.config.RateLimit, hs.config.Burst)).Methods("GET")
	r.Handle("/batch-check", rateLimitMiddleware(http.HandlerFunc(hs.batchCheckHandler), hs.config.RateLimit, hs.config.Burst)).Methods("POST")
	r.Handle("/inspect", rateLimitMiddleware(http.HandlerFunc(hs.inspectHandler), hs.config.RateLimit, hs.config.Burst)).Methods("GET")
	r.Handle("/health", http.HandlerFunc(hs.healthHandler)).Methods("GET")

	hs.httpSrv = &http.Server{
		Addr:         ":" + strconv.Itoa(port),
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		hs.logger.Info("Starting HTTP server", "port", port)
		if err := hs.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			hs.logger.Error("Could not listen on port", "port", port, "error", err)
		}
	}()
}

// shouldIncludeExplanations checks if explanations for LLM bots should be included in the response
// Using a map lookup with case-insensitive comparison for maximum compatibility and O(1) time complexity
func shouldIncludeExplanations(r *http.Request) bool {
	headerValue := strings.ToLower(r.Header.Get("__llm_bot_caller__"))
	return llmCallerValues[headerValue]
}

// If these middleware functions used to live in main.go, move them here:
func (hs *HTTPServer) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		hs.logger.Info("Request processed", "method", r.Method, "uri", r.RequestURI, "remote_addr", r.RemoteAddr, "duration", time.Since(start))
	})
}

func rateLimitMiddleware(next http.Handler, ratelimit, burst int) http.Handler {
	limiter := rate.NewLimiter(rate.Limit(ratelimit), burst)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
