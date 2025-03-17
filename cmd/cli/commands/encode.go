package commands

import (
	"bufio"
	"fmt"
	"os"

	"github.com/cipherowl-ai/addressdb/address"
	"github.com/cipherowl-ai/addressdb/store"

	"github.com/spf13/cobra"
)

var EncodeCmd = &cobra.Command{
	Use:   "encode",
	Short: "Encode addresses into a Bloom filter",
	Run:   runEncode,
}

var (
	nFlag                uint
	pFlag                float64
	inputFile            string
	outputFile           string
	privateKeyFile       string
	publicKeyFile        string
	privateKeyPassphrase string
)

func init() {
	EncodeCmd.Flags().UintVarP(&nFlag, "number", "n", 10000000, "number of elements expected")
	EncodeCmd.Flags().Float64VarP(&pFlag, "probability", "p", 0.00001, "false positive probability")
	EncodeCmd.Flags().StringVarP(&inputFile, "input", "i", "addresses.txt", "input file path")
	EncodeCmd.Flags().StringVarP(&outputFile, "output", "o", "bloomfilter.gob", "output file path")
	EncodeCmd.Flags().StringVar(&privateKeyFile, "private-key-file", "", "path to the sender private key file (optional)")
	EncodeCmd.Flags().StringVar(&publicKeyFile, "public-key-file", "", "path to the recipient public key file (optional)")
	EncodeCmd.Flags().StringVar(&privateKeyPassphrase, "private-key-passphrase", "", "passphrase for the sender private key (optional)")
}

func runEncode(_ *cobra.Command, _ []string) {
	addressHandler := &address.EVMAddressHandler{}

	options, err := configurePGPHandler()
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	options = append(options, store.WithEstimates(nFlag, pFlag))

	filter, err := store.NewBloomFilterStore(addressHandler, options...)

	if err != nil {
		fmt.Println("Error creating Bloom filter:", err)
		os.Exit(-1)
	}

	file, err := os.Open(inputFile)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		filter.AddAddress(scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading from file:", err)
		os.Exit(-1)
	}

	if err := filter.SaveToFile(outputFile); err != nil {
		fmt.Println("Error saving Bloom filter:", err)
		os.Exit(-1)
	}
	fmt.Printf("Bloom filter has been saved to %s successfully.\n", outputFile)
	// Print the statistics to verify the options were applied correctly
	filter.PrintStats()
}
