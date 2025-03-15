package commands

import (
	"bufio"
	"fmt"
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

func init() {
	BatchCheckCmd.Flags().StringVarP(&filename, "file", "f", "bloomfilter.gob", "Path to the .gob file containing the Bloom filter")
	BatchCheckCmd.Flags().StringVar(&privateKeyFile, "private-key-file", "", "path to the recipient private key file (optional)")
	BatchCheckCmd.Flags().StringVar(&publicKeyFile, "public-key-file", "", "path to the sender public key file (optional)")
	BatchCheckCmd.Flags().StringVar(&privateKeyPassphrase, "private-key-passphrase", "", "passphrase for the recipient private key (optional)")
	BatchCheckCmd.Flags().StringVar(&env, "env", "prod", "Environment (optional)")
	BatchCheckCmd.Flags().StringVar(&clientID, "client-id", "", "OAuth client ID (required)")
	BatchCheckCmd.Flags().StringVar(&clientSecret, "client-secret", "", "OAuth client secret (required)")
	BatchCheckCmd.MarkFlagRequired("client-id")
	BatchCheckCmd.MarkFlagRequired("client-secret")
}

func runBatchCheck(_ *cobra.Command, _ []string) {
	start := time.Now()
	// if err := checkAuth(clientID, clientSecret, env); err != nil {
	// 	fmt.Printf("Authentication failed: %v\n", err)
	// 	os.Exit(-1)
	// }
	filter, err := loadBloomFilter(filename)
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
