package commands

import (
	"bufio"
	"fmt"
	"github.com/cipherowl-ai/addressdb/address"
	"github.com/cipherowl-ai/addressdb/store"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var BatchCheckCmd = &cobra.Command{
	Use:   "batch-check",
	Short: "Check addresses in batch against a Bloom filter",
	Run:   runBatchCheck,
}

var batchFilename string

func init() {
	BatchCheckCmd.Flags().StringVarP(&batchFilename, "file", "f", "bloomfilter.gob", "Path to the .gob file containing the Bloom filter")
}

func runBatchCheck(_ *cobra.Command, _ []string) {
	start := time.Now()

	// Open the serialized Bloom filter file
	addressHandler := &address.EVMAddressHandler{}
	filter, err := store.NewBloomFilterStoreFromFile(batchFilename, addressHandler)
	if err != nil {
		fmt.Println("Error opening file:", err)
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
