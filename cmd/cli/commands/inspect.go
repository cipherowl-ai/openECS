package commands

import (
	"encoding/json"
	"fmt"
	"github.com/cipherowl-ai/addressdb/internal/helpers/helper"
	"os"

	"github.com/cipherowl-ai/addressdb/internal/config"
	"github.com/cipherowl-ai/addressdb/store"

	"github.com/spf13/cobra"
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
	readerConfig := &config.FilterReaderConfig{}

	inspectCmd := &cobra.Command{
		Use:   "inspect",
		Short: "Inspect the Bloom filter statistics and file size",
		Run: func(cmd *cobra.Command, args []string) {
			runInspect(cmd, readerConfig)
		},
	}

	config.BindBloomReaderFlags(inspectCmd, readerConfig)
	inspectCmd.Flags().BoolP("json", "j", false, "Output in JSON format")

	RootCmd.AddCommand(inspectCmd)

}

func runInspect(cmd *cobra.Command, readerCfg *config.FilterReaderConfig) {
	jsonOutput, _ := cmd.Flags().GetBool("json")

	// Load the bloom filter
	filter, err := helper.LoadBloomFilter(readerCfg)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	// Get the file size
	fileInfo, err := os.Stat(readerCfg.Filename)
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
