package commands

import (
	"fmt"
	"os"

	"github.com/cipherowl-ai/addressdb/address"
	"github.com/cipherowl-ai/addressdb/internal/config"
	"github.com/cipherowl-ai/addressdb/internal/helpers/helper"

	"github.com/spf13/cobra"
)

// AddCmd is the command for adding addresses to a Bloom filter, it takes a file path to the Bloom filter and an address to add
// Currently it does not support PGP encryption
func init() {
	var addCmd = &cobra.Command{
		Use:   "add",
		Short: "Add addresses to a Bloom filter",
		Run:   runAdd,
	}
	addCmd.Flags().StringP("filename", "f", "bloomfilter.gob", "Path to the .gob file containing the Bloom filter")
	addCmd.Flags().StringP("output", "o", "bloomfilter.gob", "output file path")
	addCmd.Flags().StringP("address", "a", "", "address to add")
	addCmd.MarkFlagRequired("address")

	RootCmd.AddCommand(addCmd)
}

func runAdd(cmd *cobra.Command, args []string) {
	file, _ := cmd.Flags().GetString("filename")
	output, _ := cmd.Flags().GetString("output")
	addAddress, _ := cmd.Flags().GetString("address")

	addressHandler := &address.EVMAddressHandler{}
	if err := addressHandler.Validate(addAddress); err != nil {
		fmt.Printf("Invalid address format: %v\n", err)
		os.Exit(-1)
	}

	readerCfg := &config.FilterReaderConfig{
		Filename: file,
	}

	filter, err := helper.LoadBloomFilter(readerCfg)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	filter.AddAddress(addAddress)

	if err := filter.SaveToFile(output); err != nil {
		fmt.Println("Error saving Bloom filter:", err)
		os.Exit(-1)
	}
	fmt.Printf("Bloom filter has been saved to %s successfully.\n", output)
}
