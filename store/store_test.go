package store

import (
	"github.com/cipherowl-ai/addressdb/address"
	"github.com/cipherowl-ai/addressdb/securedata"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func TestBloomFilterStoreFunctional(t *testing.T) {
	addressHandler := &address.EVMAddressHandler{}

	keys := securedata.GenerateTestKeys(t)
	aliceKeyPriv, aliceKeyPub := keys[0], keys[1]
	bobKeyPriv, bobKeyPub := keys[2], keys[3]
	chadKeyPriv := keys[4]

	aliceWriter, err := securedata.NewPGPSecureHandler(securedata.WithPrivateKey(aliceKeyPriv), securedata.WithPublicKey(bobKeyPub))
	require.NoError(t, err, "Failed to create Alice's writer")

	bobReader, err := securedata.NewPGPSecureHandler(securedata.WithPrivateKey(bobKeyPriv), securedata.WithPublicKey(aliceKeyPub))
	require.NoError(t, err, "Failed to create Bob's reader")

	chadReader, err := securedata.NewPGPSecureHandler(securedata.WithPrivateKey(chadKeyPriv), securedata.WithPublicKey(aliceKeyPub))
	require.NoError(t, err, "Failed to create Chad's reader")

	chadWriter, err := securedata.NewPGPSecureHandler(securedata.WithPrivateKey(chadKeyPriv), securedata.WithPublicKey(bobKeyPub))
	require.NoError(t, err, "Failed to create Chad's writer")

	tests := []struct {
		name        string
		writer_opts []Option
		reader_opts []Option
		wantReadErr bool
	}{
		{name: "default"},
		{name: "WithEstimates", writer_opts: []Option{WithEstimates(100, 0.0000001)}},
		{name: "WithEncryption", writer_opts: []Option{WithSecureDataHandler(aliceWriter)}, reader_opts: []Option{WithSecureDataHandler(bobReader)}},
		{name: "chad unauthorized access", writer_opts: []Option{WithSecureDataHandler(aliceWriter)}, reader_opts: []Option{WithSecureDataHandler(chadReader)}, wantReadErr: true},
		{name: "chad impersonate alice", writer_opts: []Option{WithSecureDataHandler(chadWriter)}, reader_opts: []Option{WithSecureDataHandler(bobReader)}, wantReadErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bf, err := NewBloomFilterStore(addressHandler, tt.writer_opts...)
			require.NoError(t, err, "Failed to create BloomFilterStore")

			addresses := []string{createAddress(), createAddress(), createAddress()}

			addAddressesToBloomFilter(t, bf, addresses)
			filePath := saveBloomFilterToFile(t, bf)
			defer os.Remove(filePath)

			bfReloaded, err2 := NewBloomFilterStoreFromFile(filePath, addressHandler, tt.reader_opts...)
			if tt.wantReadErr {
				require.Error(t, err2, "Expected error when reading Bloom filter")
				return
			}
			require.NoError(t, err2, "Failed to load Bloom filter from file")
			checkAddressesInBloomFilter(t, bfReloaded, addresses)
		})
	}
}

func addAddressesToBloomFilter(t *testing.T, bf *BloomFilterStore, addresses []string) {
	for _, addr := range addresses {
		if err := bf.AddAddress(addr); err != nil {
			t.Fatalf("Failed to add address %s: %v", addr, err)
		}
	}
}

func saveBloomFilterToFile(t *testing.T, bf *BloomFilterStore) string {
	filePath := os.TempDir() + "/bloomfilter.gob"
	if err := bf.SaveToFile(filePath); err != nil {
		t.Fatalf("Failed to save Bloom filter to file: %v", err)
	}
	return filePath
}

func checkAddressesInBloomFilter(t *testing.T, bf *BloomFilterStore, addresses []string) {
	for _, addr := range addresses {
		exists, err := bf.CheckAddress(addr)
		if err != nil {
			t.Fatalf("Error checking address %s: %v", addr, err)
		}
		if !exists {
			t.Errorf("Address %s should be present in the Bloom filter after reload", addr)
		}
	}
}

func createAddress() string {
	key, _ := crypto.GenerateKey()
	return crypto.PubkeyToAddress(key.PublicKey).Hex()
}
