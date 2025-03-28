package commands

import (
	"bufio"
	"fmt"
	"github.com/cipherowl-ai/addressdb/internal/helpers/helper"
	"io"
	"os"

	"github.com/cipherowl-ai/addressdb/internal/config"

	"github.com/spf13/cobra"
)

func init() {
	readerConfig := &config.FilterReaderConfig{}

	checkCmd := &cobra.Command{
		Use:   "check",
		Short: "Check addresses against a Bloom filter",
		Run: func(cmd *cobra.Command, args []string) {
			runCheck(cmd, readerConfig)
		},
	}

	config.BindBloomReaderFlags(checkCmd, readerConfig)

	RootCmd.AddCommand(checkCmd)
}

func runCheck(cmd *cobra.Command, readerCfg *config.FilterReaderConfig) {
	// if err := checkAuth(clientID, clientSecret, env); err != nil {
	// 	fmt.Printf("Authentication failed: %v\n", err)
	// 	os.Exit(-1)
	// }

	filter, err := helper.LoadBloomFilter(readerCfg)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("Enter strings to check. Press Ctrl+D to exit.")

	for {
		fmt.Print("Enter string: ")
		if !scanner.Scan() {
			if scanner.Err() == nil {
				fmt.Println("\nReached end of input. Exiting.")
			} else {
				fmt.Printf("Error reading input: %v\n", scanner.Err())
			}
			break
		}
		input := scanner.Text()
		if ok, err := filter.CheckAddress(input); err != nil {
			fmt.Println("Error checking address: ", err)
		} else if ok {
			fmt.Println("Possibly in set.")
		} else {
			fmt.Println("Definitely not in set.")
		}
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		fmt.Printf("Error reading from standard input: %v\n", err)
	}
}
