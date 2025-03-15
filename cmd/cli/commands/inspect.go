package commands

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/cipherowl-ai/addressdb/store"
	"github.com/spf13/cobra"
)

var InspectCmd = &cobra.Command{
	Use:   "inspect",
	Short: "Inspect the Bloom filter statistics and file size",
	Run:   runInspect,
}

var (
	inspectFilename             string
	inspectPrivateKeyFile       string
	inspectPublicKeyFile        string
	inspectPrivateKeyPassphrase string
	jsonOutput                  bool
)

// InspectResult represents the inspection result for JSON output
type InspectResult struct {
	Stats    store.BloomStats `json:"stats"`
	FileInfo FileInfo         `json:"file_info"`
}

// FileInfo represents file information
type FileInfo struct {
	Size      int64  `json:"size_bytes"`
	SizeHuman string `json:"size_human"`
}

func init() {
	InspectCmd.Flags().StringVarP(&inspectFilename, "file", "f", "bloomfilter.gob", "Path to the .gob file containing the Bloom filter")
	InspectCmd.Flags().StringVar(&inspectPrivateKeyFile, "private-key-file", "", "path to the recipient private key file (optional)")
	InspectCmd.Flags().StringVar(&inspectPublicKeyFile, "public-key-file", "", "path to the sender public key file (optional)")
	InspectCmd.Flags().StringVar(&inspectPrivateKeyPassphrase, "private-key-passphrase", "", "passphrase for the recipient private key (optional)")
	InspectCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")
}

func runInspect(_ *cobra.Command, _ []string) {
	// Load the bloom filter
	filter, err := loadBloomFilter(inspectFilename)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	// Get the file size
	fileInfo, err := os.Stat(inspectFilename)
	if err != nil {
		fmt.Printf("Error getting file size: %v\n", err)
		os.Exit(-1)
	}

	// Format file size in a human-readable way
	size := fileInfo.Size()
	var sizeStr string
	switch {
	case size < 1024:
		sizeStr = fmt.Sprintf("%d B", size)
	case size < 1024*1024:
		sizeStr = fmt.Sprintf("%.2f KB", float64(size)/1024)
	case size < 1024*1024*1024:
		sizeStr = fmt.Sprintf("%.2f MB", float64(size)/(1024*1024))
	default:
		sizeStr = fmt.Sprintf("%.2f GB", float64(size)/(1024*1024*1024))
	}

	// Get bloom filter statistics directly
	stats := filter.GetStats()

	if jsonOutput {
		// Create JSON output
		result := InspectResult{
			Stats: stats,
			FileInfo: FileInfo{
				Size:      size,
				SizeHuman: sizeStr,
			},
		}

		jsonData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			fmt.Printf("Error creating JSON output: %v\n", err)
			os.Exit(-1)
		}
		fmt.Println(string(jsonData))
	} else {
		// Print bloom filter statistics in human-readable format
		fmt.Println("📊 Bloom Filter Statistics:")
		fmt.Printf("  🔑 K (number of hash functions): %d\n", stats.K)
		fmt.Printf("  📏 M (bit array size): %d\n", stats.M)
		fmt.Printf("  🔢 N (number of elements added): %d\n", stats.N)
		fmt.Printf("  💪 Estimated elements capacity: %d\n", stats.EstimatedCapacity)
		fmt.Printf("📁 File Size: %s (%d bytes)\n", sizeStr, size)
	}
}
