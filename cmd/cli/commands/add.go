package commands

import (
	"fmt"
	"os"

	"github.com/cipherowl-ai/addressdb/address"

	"github.com/spf13/cobra"
)

var AddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add addresses to a Bloom filter",
	Run:   runAdd,
}

var (
	addAddress string
)

func init() {
	AddCmd.Flags().StringVarP(&filename, "file", "f", "bloomfilter.gob", "Path to the .gob file containing the Bloom filter")
	AddCmd.Flags().StringVarP(&addAddress, "address", "a", "", "address to add")
	AddCmd.MarkFlagRequired("address")
	AddCmd.Flags().StringVarP(&outputFile, "output", "o", "bloomfilter.gob", "output file path")
}

func runAdd(_ *cobra.Command, _ []string) {
	addressHandler := &address.EVMAddressHandler{}
	if err := addressHandler.Validate(addAddress); err != nil {
		fmt.Printf("Invalid address format: %v\n", err)
		os.Exit(-1)
	}

	filter, err := loadBloomFilter(filename)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	filter.AddAddress(addAddress)

	if err := filter.SaveToFile(outputFile); err != nil {
		fmt.Println("Error saving Bloom filter:", err)
		os.Exit(-1)
	}
	fmt.Printf("Bloom filter has been saved to %s successfully.\n", outputFile)
}
