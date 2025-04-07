package store

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"sync"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/cipherowl-ai/openECS/address"
	"github.com/cipherowl-ai/openECS/securedata"
)

// BloomStats represents statistics about a Bloom filter
type BloomStats struct {
	K                 uint    `json:"k"`                   // Number of hash functions
	M                 uint    `json:"m"`                   // Bit array size
	N                 uint32  `json:"n"`                   // Number of elements added
	EstimatedCapacity uint    `json:"estimated_capacity"`  // Estimated element capacity
	FalsePositiveRate float64 `json:"false_positive_rate"` // Estimated false positive rate
}

type BloomFilterStore struct {
	filter            *bloom.BloomFilter
	addressHandler    address.AddressHandler
	secureDataHandler securedata.SecureDataHandler
	mu                sync.RWMutex // Mutex to handle concurrent reloads.
}

// Option defines a functional option for BloomFilterStore.
type Option func(*BloomFilterStore)

// WithCapacity sets the capacity for the Bloom filter.
func WithEstimates(capacity uint, falsePositiveRate float64) Option {
	return func(bf *BloomFilterStore) {
		fmt.Printf("⚙️ Applying Bloom filter estimates: capacity=%d, falsePositiveRate=%f\n", capacity, falsePositiveRate)
		bf.filter = bloom.NewWithEstimates(capacity, falsePositiveRate)
	}
}

// WithSecureDataHandler sets the SecureDataHandler for the Bloom filter.
func WithSecureDataHandler(handler securedata.SecureDataHandler) Option {
	return func(bf *BloomFilterStore) {
		bf.secureDataHandler = handler // Assuming you have a field for SecureDataHandler in BloomFilterStore
	}
}

// NewBloomFilterStore creates a new Bloom filter with optional file monitoring capabilities.
func NewBloomFilterStore(addressHandler address.AddressHandler, opts ...Option) (*BloomFilterStore, error) {
	bf := &BloomFilterStore{
		addressHandler: addressHandler,
		filter:         bloom.NewWithEstimates(10000, 0.0000001), // Default values, will be overridden by options if provided
	}

	for _, opt := range opts {
		opt(bf)
	}

	return bf, nil
}

// NewBloomFilterStoreFromFile creates a new Bloom filter from a file.
func NewBloomFilterStoreFromFile(filePath string, addressHandler address.AddressHandler, opts ...Option) (*BloomFilterStore, error) {
	bf := &BloomFilterStore{
		addressHandler: addressHandler,
		filter:         bloom.NewWithEstimates(0, 0.1), // Default values
	}

	for _, opt := range opts {
		opt(bf)
	}

	if err := bf.LoadFromFile(filePath); err != nil {
		return nil, err
	}

	return bf, nil
}

// AddAddress inserts an address into the Bloom filter and encrypts the filter.
func (bf *BloomFilterStore) AddAddress(address string) error {
	// Validate and convert address
	if err := bf.addressHandler.Validate(address); err != nil {
		return err
	}

	addressBytes, err := bf.addressHandler.ToBytes(address)
	if err != nil {
		return err
	}

	bf.mu.Lock()
	defer bf.mu.Unlock()

	// Add to the Bloom filter
	bf.filter.Add(addressBytes)

	return nil
}

// CheckAddress decrypts the Bloom filter and checks if an address is in the filter.
func (bf *BloomFilterStore) CheckAddress(address string) (bool, error) {
	// Validate and convert address
	if err := bf.addressHandler.Validate(address); err != nil {
		return false, err
	}

	addressBytes, err := bf.addressHandler.ToBytes(address)
	if err != nil {
		return false, err
	}

	bf.mu.RLock()
	defer bf.mu.RUnlock()

	// Check if the address is in the filter
	return bf.filter.Test(addressBytes), nil
}

// PrintStats prints the current statistics of the Bloom filter
func (bf *BloomFilterStore) PrintStats() {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	fmt.Printf("📊 Bloom Filter Statistics:\n")
	fmt.Printf("  🔑 K (number of hash functions): %d\n", bf.filter.K())
	fmt.Printf("  📏 M (bit array size): %d\n", bf.filter.Cap())
	fmt.Printf("  🔢 N (number of elements added): %d\n", bf.filter.ApproximatedSize())
	fmt.Printf("  💪 Est. elements capacity: %d\n", bf.filter.Cap()/bf.filter.K())
	fmt.Printf("  🔄 Est. False positive rate: %f\n", bf.GetStats().FalsePositiveRate)
}

// GetStats returns the current statistics of the Bloom filter
func (bf *BloomFilterStore) GetStats() BloomStats {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	// Calculate false positive rate using the formula: (1 - e^(-k*n/m))^k
	// where k is the number of hash functions, n is the number of elements, and m is the bit array size
	k := float64(bf.filter.K())
	m := float64(bf.filter.Cap())
	n := float64(bf.filter.ApproximatedSize())

	// Avoid division by zero
	var falsePositiveRate float64
	if m > 0 {
		falsePositiveRate = math.Pow(1-math.Exp(-k*n/m), k)
	}

	return BloomStats{
		K:                 bf.filter.K(),
		M:                 bf.filter.Cap(),
		N:                 bf.filter.ApproximatedSize(),
		EstimatedCapacity: bf.filter.Cap() / bf.filter.K(),
		FalsePositiveRate: falsePositiveRate,
	}
}

func (bf *BloomFilterStore) LoadFromFile(filePath string) error {
	if filePath == "" {
		return fmt.Errorf("no file path specified for loading")
	}

	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	var filter bloom.BloomFilter
	if bf.secureDataHandler != nil {
		r, err := bf.secureDataHandler.Reader(f)
		if err != nil {
			return fmt.Errorf("failed to decrypt file: %w", err)
		}
		if _, err := filter.ReadFrom(r); err != nil {
			return fmt.Errorf("failed to read Bloom filter: %w", err)
		}
		if err := r.VerifySignature(); err != nil {
			return fmt.Errorf("failed to verify signature: %w", err)
		}
	} else {
		r := bufio.NewReader(f)

		if ok, err := securedata.IsRawEncrypted(r); err != nil {
			return fmt.Errorf("❌ failed to check if file is encrypted: %w", err)
		} else if ok {
			return fmt.Errorf("🔐 file is encrypted but no SecureDataHandler provided")
		}

		if _, err := filter.ReadFrom(r); err != nil {
			return fmt.Errorf("failed to read Bloom filter: %w", err)
		}
	}

	bf.mu.Lock()
	defer bf.mu.Unlock()

	//simple sanity check
	if filter.ApproximatedSize() == 0 {
		return fmt.Errorf("❌ failed to parse Bloom filter: %w", err)
	}

	bf.filter = &filter

	return nil
}

// SaveToFile saves the encrypted Bloom filter to the specified file.
func (bf *BloomFilterStore) SaveToFile(filePath string) error {
	if filePath == "" {
		return fmt.Errorf("no file path specified for saving")
	}

	f, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer f.Close()

	if bf.secureDataHandler != nil {
		w, err := bf.secureDataHandler.Writer(f)
		if err != nil {
			return fmt.Errorf("failed to encrypt file: %v", err)
		}
		if _, err := bf.filter.WriteTo(w); err != nil {
			return err
		}
		// print debug message encrypted
		fmt.Printf("🔒 Encrypted\n")
		return w.Close()
	} else {
		// print debug message not encrypted
		fmt.Printf("📄 Not encrypted\n")
	}

	w := bufio.NewWriter(f)
	if _, err := bf.filter.WriteTo(w); err != nil {
		return err
	}

	return w.Flush()
}
