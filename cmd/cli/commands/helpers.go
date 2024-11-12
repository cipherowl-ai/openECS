package commands

import (
	"fmt"
	"github.com/cipherowl-ai/addressdb/address"
	"github.com/cipherowl-ai/addressdb/securedata"
	"github.com/cipherowl-ai/addressdb/store"
)

// configurePGPHandler sets up the OpenPGPSecureHandler based on provided flags.
func configurePGPHandler() ([]store.Option, error) {
	pgpOptions := []securedata.Option{}
	if privateKeyFile != "" {
		pgpOptions = append(pgpOptions, securedata.WithPrivateKeyPath(privateKeyFile, privateKeyPassphrase))
	}
	if publicKeyFile != "" {
		pgpOptions = append(pgpOptions, securedata.WithPublicKeyPath(publicKeyFile))
	}

	var options []store.Option
	if len(pgpOptions) > 0 {
		pgpHandler, err := securedata.NewPGPSecureHandler(pgpOptions...)
		if err != nil {
			return nil, fmt.Errorf("error creating PGP handler: %w", err)
		}
		options = append(options, store.WithSecureDataHandler(pgpHandler))
	}

	return options, nil
}

// loadBloomFilter initializes the Bloom filter store with optional PGP handler.
func loadBloomFilter(filename string) (*store.BloomFilterStore, error) {
	options, err := configurePGPHandler()
	if err != nil {
		return nil, err
	}

	addressHandler := &address.EVMAddressHandler{}
	filter, err := store.NewBloomFilterStoreFromFile(filename, addressHandler, options...)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}

	return filter, nil
}
