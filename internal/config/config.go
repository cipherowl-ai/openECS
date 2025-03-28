package config

import (
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

type FilterReaderConfig struct {
	Filename             string
	IsHash               bool
	DecryptKey           string
	SigningKey           string
	DecryptKeyPassphrase string
}

func BindBloomReaderFlags(cmd *cobra.Command, cfg *FilterReaderConfig) {
	cmd.Flags().StringVarP(&cfg.Filename, "filename", "f", getEnv("filename", "bloomfilter.gob"), "Path to the .gob file containing the Bloom filter")
	cmd.Flags().BoolVar(&cfg.IsHash, "hash", getEnvBool("hash", false), "If true, the bloom filter stores address hashes instead of addresses strings")
	cmd.Flags().StringVar(&cfg.DecryptKey, "decrypt-key", getEnv("decrypt-key", ""), "Path to the decrypt key file")
	cmd.Flags().StringVar(&cfg.DecryptKeyPassphrase, "decrypt-key-passphrase", getEnv("decrypt-key-passphrase", ""), "Passphrase for the decrypt key")
	cmd.Flags().StringVar(&cfg.SigningKey, "signing-key", getEnv("signing-key", ""), "Path to the signing key file")
}

type FilterWriterConfig struct {
	Filename             string
	EncryptKey           string
	SigningKey           string
	SigningKeyPassphrase string
}

func BindBloomWriterFlags(cmd *cobra.Command, cfg *FilterWriterConfig) {
	cmd.Flags().StringVarP(&cfg.Filename, "output", "o", getEnv("output", "bloomfilter.gob"), "Path to the output .gob file containing the Bloom filter")
	cmd.Flags().StringVar(&cfg.EncryptKey, "encrypt-key", getEnv("encrypt-key", ""), "Path to the encrypt key file")
	cmd.Flags().StringVar(&cfg.SigningKey, "signing-key", getEnv("signing-key", ""), "Path to the signing key file")
	cmd.Flags().StringVar(&cfg.SigningKeyPassphrase, "signing-key-passphrase", getEnv("signing-key-passphrase", ""), "Passphrase for the signing key")
}

type ServiceConfig struct {
	Chain        string
	Dataset      string
	BaseURL      string
	ClientID     string
	ClientSecret string
}

func BindServiceFlags(cmd *cobra.Command, cfg *ServiceConfig) {
	cmd.Flags().StringVar(&cfg.Chain, "chain", getEnv("chain", ""), "Chain name")
	cmd.Flags().StringVar(&cfg.Dataset, "dataset", getEnv("dataset", ""), "Dataset name")
	cmd.Flags().StringVar(&cfg.BaseURL, "base-url", getEnv("base-url", ""), "Base URL for the API")
	cmd.Flags().StringVar(&cfg.ClientID, "client-id", getEnv("client-id", ""), "Client ID")
	cmd.Flags().StringVar(&cfg.ClientSecret, "client-secret", getEnv("client-secret", ""), "Client Secret")

	// Mark required flags
	cmd.MarkFlagRequired("chain")
	cmd.MarkFlagRequired("dataset")
	cmd.MarkFlagRequired("base-url")
	cmd.MarkFlagRequired("client-id")
	cmd.MarkFlagRequired("client-secret")
}

type ServerConfig struct {
	HTTPPort  int
	GRPCPort  int
	RateLimit int
	Burst     int
}

func BindServerFlags(cmd *cobra.Command, cfg *ServerConfig) {
	cmd.Flags().IntVar(&cfg.HTTPPort, "http-port", getEnvInt("http-port", 8080), "HTTP port")
	cmd.Flags().IntVar(&cfg.GRPCPort, "grpc-port", getEnvInt("grpc-port", 9090), "gRPC port")
	cmd.Flags().IntVar(&cfg.RateLimit, "rate-limit", getEnvInt("rate-limit", 20), "Rate limit")
	cmd.Flags().IntVar(&cfg.Burst, "burst", getEnvInt("burst", 5), "Burst limit")
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

func getEnvBool(key string, defaultValue bool) bool {
	value := getEnv(key, "")
	if value == "" {
		return defaultValue
	}
	boolValue, err := strconv.ParseBool(value)
	if err != nil {
		return defaultValue
	}
	return boolValue
}
