package address

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"

	"github.com/cespare/xxhash/v2"
)

// EVMAddressHandler handles Ethereum (EVM) addresses.
type EVMAddressHandler struct {
	ConvertToHash bool
}

// Validate checks if the address is a valid EVM address.
func (h *EVMAddressHandler) Validate(address string) error {
	// note we're not checking the hex characters here, only the length and prefix, the hex
	// decoding will catch invalid characters
	if len(address) != 42 || address[0] != '0' || (address[1] != 'x' && address[1] != 'X') {
		// If convertToHash is true, we can also accept valid integer strings that can be parsed as int64.
		if h.ConvertToHash {
			if _, err := strconv.ParseInt(address, 10, 64); err == nil {
				return nil
			}
		}
		return errors.New("invalid EVM address format")
	}
	return nil
}

// ToBytes converts an EVM address to bytes.
func (h *EVMAddressHandler) ToBytes(address string) ([]byte, error) {
	if h.ConvertToHash {
		// Try to parse as int64 first
		if val, err := strconv.ParseInt(address, 10, 64); err == nil {
			return int64ToBytes(val), nil // Convert int64 to bytes if successful

		}
		// If not an int64, hash the address string
		return addressToHashBytes(address)
	}

	// Regular EVM address handling
	if !has0xPrefix(address) {
		return nil, errors.New("address must start with '0x'")
	}
	return hex.DecodeString(address[2:])
}

// has0xPrefix validates str begins with '0x' or '0X'.
func has0xPrefix(str string) bool {
	return len(str) == 42 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')
}

func int64ToBytes(i int64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(i))
	return buf
}

func addressToHashBytes(address string) ([]byte, error) {
	// This function is a convenience to convert an address to its hash bytes
	// using the xxhash algorithm.
	if !has0xPrefix(address) {
		return nil, errors.New("address must start with '0x'")
	}
	h := xxhash.NewWithSeed(42)
	h.WriteString(address)
	sum := h.Sum64()

	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, sum)
	return b, nil
}
