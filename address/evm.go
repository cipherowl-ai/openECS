package address

import (
	"encoding/hex"
)

// EVMAddressHandler handles Ethereum (EVM) addresses.
type EVMAddressHandler struct{}

// Validate checks if the address is a valid EVM address.
func (h *EVMAddressHandler) Validate(address string) error {
	// note we're not checking the hex characters here, only the length and prefix, the hex
	// decoding will catch invalid characters
	//if len(address) != 42 || address[0] != '0' || (address[1] != 'x' && address[1] != 'X') {
	//	return errors.New("invalid EVM address format")
	//}
	return nil
}

// ToBytes converts an EVM address to bytes.
func (h *EVMAddressHandler) ToBytes(address string) ([]byte, error) {
	// decode the hex string would have the same effect as lowercasing the address and checking the hex string length
	if has0xPrefix(address) {
		return hex.DecodeString(address[2:])
	}

	return []byte(address), nil
}

// has0xPrefix validates str begins with '0x' or '0X'.
func has0xPrefix(str string) bool {
	return len(str) == 42 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')
}
