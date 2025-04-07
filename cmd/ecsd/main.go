package main

/**
 * Edge compliance service for Bloom filter
 * Provides HTTP endpoints to check addresses against a Bloom filter
 */
import (
	"context"
	"fmt"
	"github.com/cipherowl-ai/openECS/internal/helpers/helper"
	"log/slog"
	"os"
	"time"

	"github.com/joho/godotenv"

	"github.com/cipherowl-ai/openECS/address"
	"github.com/cipherowl-ai/openECS/ecsd"
	"github.com/cipherowl-ai/openECS/reload"
	"github.com/cipherowl-ai/openECS/store"

	"github.com/cipherowl-ai/openECS/internal/config"
	"github.com/spf13/cobra"
)

var logger = slog.Default()

var rootCmd = &cobra.Command{
	Use:   "ecsd",
	Short: "ECSd is the Edge compliance service for Bloom filter",
	RunE:  runServer,
}

var cfgBloomFilter = config.FilterReaderConfig{}
var cfgServer = config.ServerConfig{}
var cfgService = config.ServiceConfig{}

func init() {
	// Load .env file if it exists
	godotenv.Load()
}

func runServer(cmd *cobra.Command, args []string) error {
	// Initialize the config command
	config.BindBloomReaderFlags(cmd, &cfgBloomFilter)
	config.BindServerFlags(cmd, &cfgServer)
	config.BindServiceFlags(cmd, &cfgService)

	logger.Info("Starting with configuration", "http-port", cfgServer.HTTPPort, "grpc-port", cfgServer.GRPCPort, "ratelimit", cfgServer.RateLimit, "burst", cfgServer.Burst, "chain", cfgService.Chain)

	// Use cfg.* instead of global variables
	filter, err := loadBloomFilter(&cfgBloomFilter)
	if err != nil {
		return err
	}

	// Create the ReloadManager with the notifier
	manager := reloadManager(filter, &cfgService, cfgBloomFilter.Filename)
	defer manager.Stop()

	httpSrv := ecsd.NewHTTPServer(filter, manager, logger, &cfgServer)
	httpSrv.StartHTTPServer(cfgServer.HTTPPort)

	grpcSrv := ecsd.NewEcsdServer(filter, manager, logger)
	grpcSrv.StartGRPCServer(cfgServer.GRPCPort)

	httpSrv.GracefulShutdown()

	return nil
}

func loadBloomFilter(cfg *config.FilterReaderConfig) (*store.BloomFilterStore, error) {
	// Configure PGP handler if keys are provided
	// TODO refine this to use the helper functions in the securedata package

	options, err := helper.ConfigurePGPHandler(cfg.DecryptKey, cfg.DecryptKeyPassphrase, cfg.SigningKey)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	// Create address handler
	addressHandler := &address.EVMAddressHandler{ConvertToHash: cfg.IsHash}

	// First create an empty filter
	filter, err := store.NewBloomFilterStore(addressHandler, options...)
	if err != nil {
		logger.Error("Failed to create empty Bloom filter", "error", err)
		os.Exit(1)
	}
	return filter, err
}

func reloadManager(filter *store.BloomFilterStore, cfg *config.ServiceConfig, filename string) *reload.ReloadManager {
	// Create a file watcher notifier.
	notifier := reload.NewRemoteNotifier(
		cfg.Chain, cfg.Dataset, cfg.BaseURL,
		cfg.ClientID, cfg.ClientSecret, filename,
		1*time.Minute, logger)

	// Create the ReloadManager with the notifier.
	manager := reload.NewReloadManagerWithLogger(filter, notifier, logger)
	if err := manager.Start(context.Background()); err != nil {
		logger.Error("Error starting Bloom filter manager", "error", err)
		os.Exit(1)
	}

	return manager
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		logger.Error("Error executing ECSd command", "error", err)
		os.Exit(1)
	}
}
