package main

/**
 * Edge compliance service for Bloom filter
 * Provides HTTP endpoints to check addresses against a Bloom filter
 */
import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/joho/godotenv"

	"github.com/cipherowl-ai/addressdb/address"
	"github.com/cipherowl-ai/addressdb/ecsd"
	"github.com/cipherowl-ai/addressdb/reload"
	"github.com/cipherowl-ai/addressdb/securedata"
	"github.com/cipherowl-ai/addressdb/store"

	"github.com/cipherowl-ai/addressdb/ecsd/config"
	"github.com/spf13/cobra"
)

var logger = slog.Default()

var rootCmd = &cobra.Command{
	Use:   "ecsd",
	Short: "ECSd is the Edge compliance service for Bloom filter",
	RunE:  runServer,
}

func init() {
	// Load .env file if it exists
	godotenv.Load()
}

func runServer(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(cmd)
	if err != nil {
		return err
	}

	logger.Info("Starting with configuration", "http-port", cfg.Server.HTTPPort, "grpc-port", cfg.Server.GRPCPort, "ratelimit", cfg.Server.RateLimit, "burst", cfg.Server.Burst, "chain", cfg.Service.Chain)

	// Use cfg.* instead of global variables
	filter, err := loadBloomFilter(cfg)
	if err != nil {
		return err
	}

	// Create the ReloadManager with the notifier
	manager := reloadManager(filter, cfg)
	defer manager.Stop()

	httpSrv := ecsd.NewHTTPServer(filter, manager, logger, &cfg.Server)
	httpSrv.StartHTTPServer(cfg.Server.HTTPPort)

	grpcSrv := ecsd.NewEcsdServer(filter, manager, logger)
	grpcSrv.StartGRPCServer(cfg.Server.GRPCPort)

	httpSrv.GracefulShutdown()

	return nil
}

func loadBloomFilter(cfg *config.Config) (*store.BloomFilterStore, error) {
	// Configure PGP handler if keys are provided
	// TODO refine this to use the helper functions in the securedata package

	var options []store.Option
	if cfg.BloomFilter.DecryptKey != "" || cfg.BloomFilter.SigningKey != "" {
		pgpHandler, err := securedata.NewPGPSecureHandler(
			securedata.WithPrivateKeyPath(cfg.BloomFilter.DecryptKey, cfg.BloomFilter.DecryptKeyPassphrase),
			securedata.WithPublicKeyPath(cfg.BloomFilter.SigningKey),
		)
		if err != nil {
			logger.Error("Failed to create PGP handler", "error", err)
			os.Exit(1)
		}
		options = append(options, store.WithSecureDataHandler(pgpHandler))
	}

	// Create address handler
	addressHandler := &address.EVMAddressHandler{}

	// First create an empty filter
	filter, err := store.NewBloomFilterStore(addressHandler, options...)
	if err != nil {
		logger.Error("Failed to create empty Bloom filter", "error", err)
		os.Exit(1)
	}
	return filter, err
}

func reloadManager(filter *store.BloomFilterStore, cfg *config.Config) *reload.ReloadManager {
	// Create a file watcher notifier.
	notifier := reload.NewRemoteNotifier(
		cfg.Service.Chain, cfg.Service.Dataset, cfg.Service.BaseURL,
		cfg.Service.ClientID, cfg.Service.ClientSecret, cfg.BloomFilter.Filename,
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
