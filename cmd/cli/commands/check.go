package commands

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

var CheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Check addresses against a Bloom filter",
	Run:   runCheck,
}

var (
	filename     string
	env          string
	clientID     string
	clientSecret string
)

func init() {
	CheckCmd.Flags().StringVarP(&filename, "file", "f", "bloomfilter.gob", "Path to the .gob file containing the Bloom filter")
	CheckCmd.Flags().StringVar(&env, "env", "prod", "Environment (optional)")
	CheckCmd.Flags().StringVar(&publicKeyFile, "public-key-file", "", "path to the sender public key file (optional)")
}

func runCheck(_ *cobra.Command, _ []string) {
	// if err := checkAuth(clientID, clientSecret, env); err != nil {
	// 	fmt.Printf("Authentication failed: %v\n", err)
	// 	os.Exit(-1)
	// }

	filter, err := loadBloomFilter(filename)
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
