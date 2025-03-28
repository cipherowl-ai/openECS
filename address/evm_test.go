package address

import (
	"strconv"
	"testing"

	"github.com/cespare/xxhash/v2"
	"github.com/stretchr/testify/assert"
)

func TestEVMAddressHandler_Validate(t *testing.T) {
	handler := &EVMAddressHandler{}

	tests := []struct {
		name    string
		address string
		valid   bool
	}{
		{"lower case", "0x1234567890abcdef1234567890abcdef12345678", true},
		{"mixed case", "0X1234567890ABCDEF1234567890ABCDEF12345678", true},
		{"no prefix", "1234567890abcdef1234567890abcdef12345678", false},
		{"too short", "0x1234567890abcdef1234567890abcdef1234567", false},
		{"too long", "0x1234567890abcdef1234567890abcdef123456789", false},
	}

	for _, test := range tests {
		err := handler.Validate(test.address)
		if (err == nil) != test.valid {
			t.Errorf("Validate(%q) = %v; want valid = %v", test.address, err, test.valid)
		}
	}
}

func TestEVMAddressHandler_ToBytes(t *testing.T) {
	handler := &EVMAddressHandler{}

	tests := []struct {
		name    string
		address string
		bytes   []byte
		err     bool
	}{
		{"lower case", "0x1234567890abcdef1234567890abcdef12345678", []byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78}, false},
		{"mixed case", "0X1234567890ABCDEF1234567890ABCDEF12345678", []byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78}, false},
		{"odd hex length", "0x1234567890abcdef1234567890abcdef1234567", nil, true},
		{"invalid hex", "0xG234567890abcdef1234567890abcdef12345678", nil, true},
	}

	for _, test := range tests {
		result, err := handler.ToBytes(test.address)
		if (err != nil) != test.err {
			t.Errorf("ToBytes(%q) = %v; want error = %v", test.address, err, test.err)
		}
		if !test.err && !equalBytes(result, test.bytes) {
			t.Errorf("ToBytes(%q) = %v; want %v", test.address, result, test.bytes)
		}
	}
}

func TestEVMAddressHandler_XXHash(t *testing.T) {
	address := "0x2d5685cb8517ad609323371a5e6a0683cdf264a8"
	hasher := xxhash.NewWithSeed(42)
	hasher.WriteString(address)
	hash := int64(hasher.Sum64())
	assert.Equal(t, hash, int64(-593705382299969669))

	hasher.ResetWithSeed(42)
	hasher.WriteString(address)
	hash2 := int64(hasher.Sum64())
	assert.Equal(t, hash2, int64(-593705382299969669))
}

func TestEVMAddressHandler_ToBytes_ConvertToHash(t *testing.T) {
	tests := []struct {
		name    string
		address string
		hash    string
	}{
		{
			name:    "basic address",
			address: "0x2d5685cb8517ad609323371a5e6a0683cdf264a8",
			hash:    "-593705382299969669",
		},
		{
			name:    "all zeros",
			address: "0x1937d9981d91a11c07c511d50fcbce4763f012a2",
			hash:    "-7452645531153106818",
		},
		{
			name:    "all fs",
			address: "0x2c54669ee14014880a941198f67b4aebcc9fcc7b",
			hash:    "4905205312255835457",
		},
	}

	handler := &EVMAddressHandler{ConvertToHash: true}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert the address to bytes
			b1, err := handler.ToBytes(tt.address)
			assert.NoError(t, err)

			// Convert the hash string to bytes
			b2, err := handler.ToBytes(tt.hash)
			assert.NoError(t, err)

			// Both conversions should yield the same bytes
			assert.Equal(t, b1, b2, "Bytes from address and hash string should match for %s", tt.name)

			// Verify the hash string matches what we expect
			hasher := xxhash.NewWithSeed(42)
			hasher.WriteString(tt.address)
			hash := int64(hasher.Sum64())
			assert.Equal(t, tt.hash, strconv.FormatInt(hash, 10), "Hash string should match xxhash of address for %s", tt.name)
		})
	}
}

// Helper function to compare byte slices
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
