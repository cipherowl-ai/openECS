package commands

import (
	"fmt"
	"log"
	"os"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/spf13/cobra"
)

var AddressGenCmd = &cobra.Command{
	Use:   "generate-addresses",
	Short: "Generate Ethereum addresses",
	Run:   runAddressGenerator,
}

func init() {
	addressGenCmd := &cobra.Command{
		Use:   "generate-addresses",
		Short: "Generate Ethereum addresses",
		Run:   runAddressGenerator,
	}
	addressGenCmd.Flags().IntP("n", "n", 1000000, "number of addresses to generate")
	addressGenCmd.Flags().StringP("output", "o", "addresses.txt", "output file for the addresses")

	RootCmd.AddCommand(addressGenCmd)
}

func runAddressGenerator(cmd *cobra.Command, _ []string) {
	count, _ := cmd.Flags().GetInt("n")
	addressFile, _ := cmd.Flags().GetString("output")

	// Open the output file
	file, err := os.Create(addressFile)
	if err != nil {
		log.Fatalf("Failed to open output file: %v", err)
	}
	defer file.Close()

	for i := 0; i < count; i++ {
		key, err := crypto.GenerateKey()
		if err != nil {
			log.Fatalf("Failed to generate key: %v", err)
		}
		address := crypto.PubkeyToAddress(key.PublicKey).Hex() // Get the hex representation of the address

		// Write the address to the file
		if _, err := file.WriteString(address + "\n"); err != nil {
			log.Fatalf("Failed to write to file: %v", err)
		}
	}
	fmt.Printf("Generated %d Ethereum addresses\n", count)
}
