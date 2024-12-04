package address

import "github.com/btcsuite/btcd/btcutil"

// BitcoinAddressHandler handles Bitcoin addresses.
type BitcoinAddressHandler struct{}

// Validate checks if the address is a valid Bitcoin address.
func (h *BitcoinAddressHandler) Validate(address string) error {
	_, err := btcutil.DecodeAddress(address, nil)
	if err != nil {
		return err
	}
	return nil
}

// ToBytes converts a Bitcoin address to its byte slice representation.
func (h *BitcoinAddressHandler) ToBytes(address string) ([]byte, error) {
	addr, err := btcutil.DecodeAddress(address, nil)
	if err != nil {
		return nil, err
	}
	return addr.ScriptAddress(), nil
}
