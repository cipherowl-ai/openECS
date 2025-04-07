package commands

import (
	"bufio"
	"fmt"
	"github.com/cipherowl-ai/openECS/internal/helpers/helper"
	"io"
	"os"
	"time"

	"github.com/cipherowl-ai/openECS/internal/config"
	"github.com/spf13/cobra"
)

func init() {
	readerConfig := &config.FilterReaderConfig{}

	batchCheckCmd := &cobra.Command{
		Use:   "batch-check",
		Short: "Check addresses in batch against a Bloom filter",
		Run: func(cmd *cobra.Command, args []string) {
			runBatchCheck(cmd, readerConfig)
		},
	}

	config.BindBloomReaderFlags(batchCheckCmd, readerConfig)

	RootCmd.AddCommand(batchCheckCmd)
}

func runBatchCheck(cmd *cobra.Command, readerCfg *config.FilterReaderConfig) {
	start := time.Now()
	// if err := checkAuth(clientID, clientSecret, env); err != nil {
	// 	fmt.Printf("Authentication failed: %v\n", err)
	// 	os.Exit(-1)
	// }
	filter, err := helper.LoadBloomFilter(readerCfg)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	elapsed := time.Since(start)
	fmt.Printf("> Time taken to load bloomfilter: %v\n", elapsed)

	// Create a scanner to read input from standard input
	scanner := bufio.NewScanner(os.Stdin)

	// Measure the time it takes to check the bloom filter
	start = time.Now()

	// Read from standard input, till EOF, and check if the string is in the bloom filter
	for {
		if !scanner.Scan() {
			if scanner.Err() != nil {
				// Print to stderr
				fmt.Fprintf(os.Stderr, "Error reading from standard input: %v\n", scanner.Err())
			}
			break
		}
		input := scanner.Text()
		// Only handle non-existing entries
		if ok, err := filter.CheckAddress(input); err != nil {
			fmt.Println("Error checking address:", err)
		} else if !ok {
			fmt.Println("NOT in set:", input)
		}
	}
	elapsed = time.Since(start)
	fmt.Printf("> Time taken to check bloomfilter: %v\n", elapsed)

	if err := scanner.Err(); err != nil && err != io.EOF {
		fmt.Fprintf(os.Stderr, "Error reading from standard input: %v\n", err)
	}
}
