package main

import (
	"fmt"
	"os"

	"github.com/cipherowl-ai/addressdb/cmd/cli/commands"

	"github.com/spf13/cobra"
)

func main() {
	var rootCmd = &cobra.Command{Use: "bloom-cli"}

	// Add commands
	rootCmd.AddCommand(commands.EncodeCmd)
	rootCmd.AddCommand(commands.CheckCmd)
	rootCmd.AddCommand(commands.BatchCheckCmd)
	rootCmd.AddCommand(commands.AddressGenCmd)
	rootCmd.AddCommand(commands.AddCmd)
	rootCmd.AddCommand(commands.InspectCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
