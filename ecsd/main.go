package main

/**
 * Edge compliance service for Bloom filter
 * Provides HTTP endpoints to check addresses against a Bloom filter
 */
import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cipherowl-ai/addressdb/address"
	"github.com/cipherowl-ai/addressdb/reload"
	"github.com/cipherowl-ai/addressdb/securedata"
	"github.com/cipherowl-ai/addressdb/store"

	pb "github.com/cipherowl-ai/addressdb/proto"
	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var (
	filter               *store.BloomFilterStore
	logger               = log.New(os.Stdout, "ECSd: ", log.LstdFlags)
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

var (
	chain       string
	dataset     string
	filename    string
	port        int
	grpcPort    int
	ratelimit_v int
	burst_v     int
)

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

var rootCmd = &cobra.Command{
	Use:   "ecsd",
	Short: "ECSd is the Edge compliance service for Bloom filter",
	Run:   runServer,
}

func init() {
	viper.SetEnvPrefix("CO")
	viper.AutomaticEnv()

	// Initialize our Cobra flags in init(), so they're set before rootCmd.Execute() runs
	rootCmd.Flags().StringVarP(&filename, "filename", "f", "bloomfilter.gob", "Path to the .gob file containing the Bloom filter")
	rootCmd.Flags().IntVarP(&port, "port", "p", 8080, "Port to listen on for HTTP")
	rootCmd.Flags().IntVarP(&grpcPort, "grpc-port", "", 9090, "Port to listen on for gRPC")
	rootCmd.Flags().IntVarP(&ratelimit_v, "ratelimit", "r", 20, "Ratelimit")
	rootCmd.Flags().IntVarP(&burst_v, "burst", "b", 5, "Burst")
	rootCmd.Flags().StringVar(&privateKeyFile, "private-key-file", "", "Path to the private key file (optional)")
	rootCmd.Flags().StringVar(&publicKeyFile, "public-key-file", "", "Path to the public key file (optional)")

	// ↓ Simplify by removing viper.GetString(...) as the default values
	//    so that Viper manages actual values via BindPFlag
	rootCmd.Flags().StringVar(&clientID, "client-id", "", "Client ID (env: CO_CLIENT_ID)")
	rootCmd.Flags().StringVar(&clientSecret, "client-secret", "", "Client Secret (env: CO_CLIENT_SECRET)")
	rootCmd.Flags().StringVar(&baseURL, "base-url", "", "Base URL (env: CO_BASE_URL)")
	rootCmd.Flags().StringVar(&chain, "chain", "", "Chain (env: CO_CHAIN)")
	rootCmd.Flags().StringVar(&dataset, "dataset", "", "Dataset (env: CO_DATASET)")
	rootCmd.Flags().StringVar(&environment, "environment", "", "Environment (env: CO_ENV)")
	rootCmd.Flags().StringVar(&privateKeyPassphrase, "key-passphrase", "", "Key passphrase (env: KEY_PASSPHRASE)")

	// ↓ Bind those flags to environment vars so Viper merges them
	viper.BindPFlag("client-id", rootCmd.Flags().Lookup("client-id"))
	viper.BindPFlag("client-secret", rootCmd.Flags().Lookup("client-secret"))
	viper.BindPFlag("base-url", rootCmd.Flags().Lookup("base-url"))
	viper.BindPFlag("environment", rootCmd.Flags().Lookup("environment"))
	viper.BindPFlag("key-passphrase", rootCmd.Flags().Lookup("key-passphrase"))
	viper.BindPFlag("chain", rootCmd.Flags().Lookup("chain"))
	viper.BindPFlag("dataset", rootCmd.Flags().Lookup("dataset"))
}

func runServer(cmd *cobra.Command, args []string) {
	logger.Printf("Starting with configuration: http-port=%d, grpc-port=%d, ratelimit=%d, burst=%d, env=%s",
		port, grpcPort, ratelimit_v, burst_v, environment)

	loadBloomFilter()

	// Record initial load time - to be 1970-01-01 00:00:00 UTC
	lastFilterLoadTime = time.Unix(0, 0).UTC() // 1970-01-01 00:00:00 UTC

	// Create the ReloadManager with the notifier.
	manager := reloadManager(filename)
	defer manager.Stop()

	// Instead, call a helper function from http_server.go
	httpSrv := StartHTTPServer(port)

	// Start gRPC server in a goroutine
	go func() {
		lis, err := net.Listen("tcp", fmt.Sprintf(":%d", grpcPort))
		if err != nil {
			logger.Fatalf("Failed to listen for gRPC: %v", err)
		}

		s := grpc.NewServer()
		pb.RegisterECSdServer(s, &ecsdServer{})
		// Enable reflection for debugging
		reflection.Register(s)

		logger.Printf("Starting gRPC server on port %d", grpcPort)
		if err := s.Serve(lis); err != nil {
			logger.Fatalf("Failed to serve gRPC: %v", err)
		}
	}()

	gracefulShutdown(httpSrv)
}

func loadBloomFilter() error {
	// Configure PGP handler if keys are provided
	// TODO refine this to use the helper functions in the securedata package

	var options []store.Option
	if privateKeyFile != "" || publicKeyFile != "" {
		pgpHandler, err := securedata.NewPGPSecureHandler(
			securedata.WithPrivateKeyPath(privateKeyFile, privateKeyPassphrase),
			securedata.WithPublicKeyPath(publicKeyFile),
		)
		if err != nil {
			logger.Fatalf("Failed to create PGP handler: %v", err)
		}
		options = append(options, store.WithSecureDataHandler(pgpHandler))
	}

	// Create address handler
	addressHandler := &address.EVMAddressHandler{}

	// First create an empty filter
	var err error
	filter, err = store.NewBloomFilterStoreFromFile(filename, addressHandler, options...)
	if err != nil {
		logger.Fatalf("Failed to create empty Bloom filter: %v", err)
	}
	return err
}

func reloadManager(filename string) *reload.ReloadManager {
	// Create a file watcher notifier.
	notifier := reload.NewRemoteNotifier(chain, dataset, baseURL, clientID, clientSecret, filename, 1*time.Minute)

	// Create the ReloadManager with the notifier.
	manager := reload.NewReloadManager(filter, notifier)
	if err := manager.Start(context.Background()); err != nil {
		logger.Fatalf("Error starting Bloom filter manager: %v", err)
	}

	return manager
}

func main() {
	// Load .env file if it exists
	godotenv.Load()

	// Execute the Cobra command; if there's an error, log it.
	if err := rootCmd.Execute(); err != nil {
		logger.Fatalf("Error executing ECSd command: %v", err)
	}
}
