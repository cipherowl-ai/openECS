package store

import (
	"github.com/bits-and-blooms/bloom/v3"
	"github.com/cipherowl-ai/openECS/address"
	"github.com/ethereum/go-ethereum/crypto"
	"log"
	"math/rand"
	"strings"
	"testing"
)

func BenchmarkAddAddress(b *testing.B) {
	addressHandler := &address.EVMAddressHandler{}
	count := 100000
	bf, err := NewBloomFilterStore(addressHandler, WithEstimates(uint(count), 0.000001))
	if err != nil {
		b.Fatalf("Failed to create BloomFilterStore: %v", err)
	}

	addresses := make([]string, count)
	for i := 0; i < count; i++ {
		key, err := crypto.GenerateKey()
		if err != nil {
			log.Fatalf("Failed to generate key: %v", err)
		}
		addresses[i] = crypto.PubkeyToAddress(key.PublicKey).Hex()
	}

	b.ResetTimer() // Reset the timer before the benchmark loop
	for i := 0; i < b.N; i++ {
		address := addresses[i%count]
		if err := bf.AddAddress(address); err != nil {
			b.Fatalf("Failed to add address: %v", err)
		}
	}
}

func BenchmarkBloomFilterTestNaive(b *testing.B) {
	count := 100000
	bf := bloom.NewWithEstimates(uint(count), 0.000001)

	addresses := make([]string, count)
	for i := 0; i < count; i++ {
		key, err := crypto.GenerateKey()
		if err != nil {
			log.Fatalf("Failed to generate key: %v", err)
		}
		addresses[i] = crypto.PubkeyToAddress(key.PublicKey).Hex()
	}

	b.ResetTimer() // Reset the timer before the benchmark loop
	for i := 0; i < b.N; i++ {
		address := addresses[i%count]
		bf.AddString(strings.ToLower(address))
	}
}

func BenchmarkCheckAddress(b *testing.B) {
	addressHandler := &address.EVMAddressHandler{}
	count := 100000
	bf, err := NewBloomFilterStore(addressHandler, WithEstimates(uint(count), 0.000001))
	if err != nil {
		b.Fatalf("Failed to create BloomFilterStore: %v", err)
	}

	addresses := make([]string, count)
	for i := 0; i < count; i++ {
		key, err := crypto.GenerateKey()
		if err != nil {
			log.Fatalf("Failed to generate key: %v", err)
		}
		addresses[i] = crypto.PubkeyToAddress(key.PublicKey).Hex()
		if rand.Intn(2) < 1 {
			bf.AddAddress(addresses[i])
		}
	}

	b.ResetTimer() // Reset the timer before the benchmark loop
	for i := 0; i < b.N; i++ {
		address := addresses[i%count]
		bf.CheckAddress(address)
	}
}

func BenchmarkBloomFilterNaiveCheck(b *testing.B) {
	count := 100000
	bf := bloom.NewWithEstimates(uint(count), 0.000001)

	addresses := make([]string, count)
	for i := 0; i < count; i++ {
		key, err := crypto.GenerateKey()
		if err != nil {
			log.Fatalf("Failed to generate key: %v", err)
		}
		addresses[i] = crypto.PubkeyToAddress(key.PublicKey).Hex()
		if rand.Intn(2) < 1 {
			bf.AddString(strings.ToLower(addresses[i]))
		}
	}

	b.ResetTimer() // Reset the timer before the benchmark loop
	for i := 0; i < b.N; i++ {
		address := addresses[i%count]
		bf.TestString(strings.ToLower(address))
	}
}
