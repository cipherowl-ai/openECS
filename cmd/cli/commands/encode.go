package commands

import (
	"bufio"
	"fmt"
	"github.com/cipherowl-ai/addressdb/address"
	"github.com/cipherowl-ai/addressdb/store"
	"os"

	"github.com/spf13/cobra"
)

var EncodeCmd = &cobra.Command{
	Use:   "encode",
	Short: "Encode addresses into a Bloom filter",
	Run:   runEncode,
}

var (
	nFlag      uint
	pFlag      float64
	inputFile  string
	outputFile string
)

func init() {
	EncodeCmd.Flags().UintVarP(&nFlag, "number", "n", 10000000, "number of elements expected")
	EncodeCmd.Flags().Float64VarP(&pFlag, "probability", "p", 0.00001, "false positive probability")
	EncodeCmd.Flags().StringVarP(&inputFile, "input", "i", "addresses.txt", "input file path")
	EncodeCmd.Flags().StringVarP(&outputFile, "output", "o", "bloomfilter.gob", "output file path")
}

func runEncode(_ *cobra.Command, _ []string) {
	addressHandler := &address.EVMAddressHandler{}
	filter, err := store.NewBloomFilterStore(addressHandler, store.WithEstimates(nFlag, pFlag))
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
	fmt.Println("Bloom filter has been serialized successfully.")
}
