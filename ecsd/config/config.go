package config

import (
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

type Config struct {
	// File configuration
	BloomFilter BloomFilterConfig

	// Server configuration
	Server ServerConfig

	// Service configuration
	Service ServiceConfig
}

type BloomFilterConfig struct {
	Filename             string
	DecryptKey           string
	SigningKey           string
	DecryptKeyPassphrase string
}

type ServerConfig struct {
	HTTPPort  int
	GRPCPort  int
	RateLimit int
	Burst     int
}

type ServiceConfig struct {
	Chain        string
	Dataset      string
	BaseURL      string
	ClientID     string
	ClientSecret string
}

func Load(cmd *cobra.Command) (*Config, error) {
	// Define flags with environment variable defaults and store the pointers
	filename := cmd.Flags().StringP("filename", "f", getEnv("filename", "bloomfilter.gob"), "Path to the .gob file containing the Bloom filter")
	httpPort := cmd.Flags().IntP("port", "p", getEnvInt("port", 8080), "Port to listen on for HTTP")
	grpcPort := cmd.Flags().Int("grpc-port", getEnvInt("grpc-port", 9090), "Port to listen on for gRPC")
	rateLimit := cmd.Flags().IntP("ratelimit", "r", getEnvInt("ratelimit", 20), "Rate limit")
	burst := cmd.Flags().IntP("burst", "b", getEnvInt("burst", 5), "Burst limit")
	decryptKey := cmd.Flags().String("decrypt-key", getEnv("decrypt-key", ""), "Path to the decrypt key file")
	signingKey := cmd.Flags().String("signing-key", getEnv("signing-key", ""), "Path to the signing key file")
	decryptKeyPassphrase := cmd.Flags().String("decrypt-key-passphrase", getEnv("decrypt-key-passphrase", ""), "Passphrase for the decrypt key")
	chain := cmd.Flags().String("chain", getEnv("chain", ""), "Chain name")
	dataset := cmd.Flags().String("dataset", getEnv("dataset", ""), "Dataset name")
	baseURL := cmd.Flags().String("base-url", getEnv("base-url", ""), "Base URL for the API")
	clientID := cmd.Flags().String("client-id", getEnv("client-id", ""), "Client ID")
	clientSecret := cmd.Flags().String("client-secret", getEnv("client-secret", ""), "Client Secret")

	// Mark required flags
	cmd.MarkFlagRequired("chain")
	cmd.MarkFlagRequired("dataset")
	cmd.MarkFlagRequired("base-url")
	cmd.MarkFlagRequired("client-id")
	cmd.MarkFlagRequired("client-secret")

	// Create config from flag values
	cfg := &Config{
		BloomFilter: BloomFilterConfig{
			Filename:             *filename,
			DecryptKey:           *decryptKey,
			SigningKey:           *signingKey,
			DecryptKeyPassphrase: *decryptKeyPassphrase,
		},
		Server: ServerConfig{
			HTTPPort:  *httpPort,
			GRPCPort:  *grpcPort,
			RateLimit: *rateLimit,
			Burst:     *burst,
		},
		Service: ServiceConfig{
			Chain:        *chain,
			Dataset:      *dataset,
			BaseURL:      *baseURL,
			ClientID:     *clientID,
			ClientSecret: *clientSecret,
		},
	}

	return cfg, nil
}

// Helper function to get environment variables with defaults
func getEnv(key, defaultValue string) string {
	value := os.Getenv("CO_" + strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(key, "-", "_"), ".", "_")))
	if value == "" {
		return defaultValue
	}
	return value
}

// Helper function to get integer environment variables with defaults
func getEnvInt(key string, defaultValue int) int {
	value := getEnv(key, "")
	if value == "" {
		return defaultValue
	}
	intValue, err := strconv.Atoi(value)
	if err != nil {
		return defaultValue
	}
	return intValue
}
