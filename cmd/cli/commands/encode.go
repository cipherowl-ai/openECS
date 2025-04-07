package commands

import (
	"bufio"
	"fmt"
	"os"

	"github.com/cipherowl-ai/openECS/internal/helpers/helper"

	"github.com/cipherowl-ai/openECS/address"
	"github.com/cipherowl-ai/openECS/internal/config"
	"github.com/cipherowl-ai/openECS/store"

	"github.com/spf13/cobra"
)

func init() {
	writerConfig := &config.FilterWriterConfig{}

	var encodeCmd = &cobra.Command{
		Use:   "encode",
		Short: "Encode addresses into a Bloom filter",
		Run: func(cmd *cobra.Command, args []string) {
			runEncode(cmd, writerConfig)
		},
	}
	config.BindBloomWriterFlags(encodeCmd, writerConfig)

	encodeCmd.Flags().UintP("number", "n", 10000000, "number of elements expected")
	encodeCmd.Flags().Float64P("probability", "p", 0.00001, "false positive probability")
	encodeCmd.Flags().StringP("input", "i", "addresses.txt", "input file path")
	encodeCmd.Flags().BoolP("hash", "H", false, "hashes the addressees, this also accepts the hash as a string")

	RootCmd.AddCommand(encodeCmd)
}

func runEncode(cmd *cobra.Command, writerCfg *config.FilterWriterConfig) {
	nFlag, _ := cmd.Flags().GetUint("number")
	pFlag, _ := cmd.Flags().GetFloat64("probability")
	inputFile, _ := cmd.Flags().GetString("input")
	hashFlag, _ := cmd.Flags().GetBool("hash")

	addressHandler := &address.EVMAddressHandler{ConvertToHash: hashFlag}

	options, err := helper.ConfigurePGPHandler(writerCfg.SigningKey, writerCfg.SigningKeyPassphrase, writerCfg.EncryptKey)
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

	if err := filter.SaveToFile(writerCfg.Filename); err != nil {
		fmt.Println("Error saving Bloom filter:", err)
		os.Exit(-1)
	}
	fmt.Printf("Bloom filter has been saved to %s successfully.\n", writerCfg.Filename)
	// Print the statistics to verify the options were applied correctly
	filter.PrintStats()
}
