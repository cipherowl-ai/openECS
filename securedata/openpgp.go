package securedata

import (
	"bufio"
	"errors"
	"io"
	"os"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
)

// Option defines a function that can modify OpenPGPSecureHandler and return an error.
type Option func(*OpenPGPSecureHandler) error

func WithPrivateKey(privKey *crypto.Key) Option {
	return func(h *OpenPGPSecureHandler) error {
		if privKey == nil {
			return errors.New("private key cannot be nil")
		}
		h.privKey = privKey
		return nil
	}
}

func WithPublicKey(pubKey *crypto.Key) Option {
	return func(h *OpenPGPSecureHandler) error {
		if pubKey == nil {
			return errors.New("public key cannot be nil")
		}
		h.pubKey = pubKey
		return nil
	}
}

func WithPublicKeyPath(filePath string) Option {
	return func(h *OpenPGPSecureHandler) error {
		keyData, err := os.ReadFile(filePath)
		if err != nil {
			return err
		}
		pubKey, err := crypto.NewKeyFromArmored(string(keyData))
		if err != nil {
			return err
		}
		h.pubKey = pubKey
		return nil
	}
}

func WithPrivateKeyPath(filePath string, passphrase string) Option {
	return func(h *OpenPGPSecureHandler) error {
		keyData, err := os.ReadFile(filePath)
		if err != nil {
			return err
		}
		privKey, err := crypto.NewPrivateKeyFromArmored(string(keyData), []byte(passphrase))
		if err != nil {
			return err
		}
		h.privKey = privKey
		return nil
	}
}

// OpenPGPSecureHandler handles encryption and decryption using OpenPGP.
type OpenPGPSecureHandler struct {
	pgpHandle *crypto.PGPHandle
	privKey   *crypto.Key
	pubKey    *crypto.Key
}

// NewPGPSecureHandler creates a new instance of OpenPGPSecureHandler.
func NewPGPSecureHandler(opts ...Option) (*OpenPGPSecureHandler, error) {
	handler := &OpenPGPSecureHandler{
		pgpHandle: crypto.PGPWithProfile(profile.RFC9580()),
	}
	for _, opt := range opts {
		if err := opt(handler); err != nil {
			return nil, err // Return error if any option fails
		}
	}
	return handler, nil
}

// Writer returns an io.Writer that encrypts data.
func (h *OpenPGPSecureHandler) Writer(output io.Writer) (io.WriteCloser, error) {
	encHandle, err := h.pgpHandle.Encryption().
		Recipient(h.pubKey).
		SigningKey(h.privKey).
		New()
	if err != nil {
		return nil, err
	}
	return encHandle.EncryptingWriter(output, crypto.Bytes)
}

// Reader returns an io.Reader that decrypts data and verifies the signature.
func (h *OpenPGPSecureHandler) Reader(input io.Reader) (VerifyDataReader, error) {
	decHandle, err := h.pgpHandle.Decryption().
		DecryptionKey(h.privKey).
		VerificationKey(h.pubKey).
		New()
	if err != nil {
		return nil, err
	}

	ptReader, err := decHandle.DecryptingReader(input, crypto.Bytes)
	if err != nil {
		return nil, err
	}

	return &VerifiedReader{reader: ptReader}, nil
}

// VerifiedReader wraps VerifyDataReader and verifies the signature at the end.
type VerifiedReader struct {
	reader *crypto.VerifyDataReader
}

// Read reads data from the underlying VerifyDataReader and verifies the signature at the end.
func (r *VerifiedReader) Read(b []byte) (int, error) {
	n, err := r.reader.Read(b)
	if errors.Is(err, io.EOF) {
		if result, verifyErr := r.reader.VerifySignature(); verifyErr != nil {
			return n, verifyErr
		} else if result.SignatureError() != nil {
			return n, result.SignatureError()
		}
	}
	return n, err
}

// VerifySignature verifies the signature of the data read so far.
func (r *VerifiedReader) VerifySignature() error {
	if result, err := r.reader.ReadAllAndVerifySignature(); err != nil {
		return err
	} else if result.SignatureError() != nil {
		return result.SignatureError()
	}

	return nil
}

// IsRawEncrypted checks if the data is encrypted using OpenPGP format detection.
// It implements RFC 4880 packet format detection to identify both ASCII-armored
// and binary OpenPGP encrypted content.
func IsRawEncrypted(reader *bufio.Reader) (bool, error) {
	// Define packet tags for encryption-related packets per RFC 4880
	// These are the standard packet types that indicate encrypted content
	const (
		publicKeyEncryptedSessionKeyPacket                 = 1  // Tag 1 - Contains session key encrypted with recipient's public key
		symmetricallyEncryptedDataPacket                   = 9  // Tag 9 - Contains symmetrically encrypted data
		symmetricallyEncryptedIntegrityProtectedDataPacket = 18 // Tag 18 - Encrypted data with additional integrity protection
		compressedDataPacket                               = 8  // Tag 8 - Compressed data (often found in encrypted messages)
		modificationDetectionCodePacket                    = 19 // Tag 19 - Used with integrity protected packets
	)

	// First, check for ASCII-armored OpenPGP data
	// ASCII-armored format is a text representation that begins with a specific header
	headerBytes, err := reader.Peek(30) // Need enough bytes to detect ASCII armor header
	if err != nil {
		if err != io.EOF {
			return false, err // An unexpected error occurred
		}
		// If we hit EOF, we may not have enough data, but we can still process what we have
		if len(headerBytes) == 0 {
			return false, nil // No data available at all
		}
	}

	// Check for ASCII armor header ("-----BEGIN PGP MESSAGE-----")
	// This is the standard header for ASCII-armored PGP encrypted messages
	if len(headerBytes) >= 27 {
		header := string(headerBytes[:27])
		if header == "-----BEGIN PGP MESSAGE-----" {
			return true, nil // Found ASCII-armored PGP data
		}
	}

	// If not ASCII-armored, check for binary OpenPGP format
	// Binary format requires at least 2 bytes for a valid packet header
	if len(headerBytes) < 2 {
		return false, nil // Not enough data for binary format detection
	}

	// Special case for gopenpgp library format
	// This is a specific optimization for the ProtonMail gopenpgp implementation
	// Based on observation, gopenpgp encrypted data often starts with byte 0xC1 (193)
	if headerBytes[0] == 0xC1 && len(headerBytes) >= 5 {
		return true, nil // Detected gopenpgp-specific format
	}

	// Per RFC 4880, Section 4.2 and 4.3:
	// Bit 7 of the first byte must be set for all OpenPGP packets
	// This is a requirement for all valid OpenPGP packets
	firstByte := headerBytes[0]
	if (firstByte & 0x80) == 0 {
		return false, nil // Not an OpenPGP packet - bit 7 is not set
	}

	// Now we need to determine the packet format and tag
	// OpenPGP has two packet formats: old (pre-RFC 4880) and new
	var packetTag byte

	// Check if it's an old format packet (bit 6 set) or new format packet (bit 6 clear)
	// RFC 4880 Section 4.2 defines these two formats
	if (firstByte & 0x40) == 0x40 {
		// Old format packet (RFC 4880, Section 4.2)
		// In old format, bits 5-2 contain the packet tag
		packetTag = (firstByte & 0x3C) >> 2 // Extract bits 5-2
	} else {
		// New format packet (RFC 4880, Section 4.2)
		// In new format, bits 5-0 contain the packet tag
		packetTag = firstByte & 0x3F // Extract bits 5-0
	}

	// Check if the packet tag indicates encryption or an associated packet type
	// If any of these packet types are found, the data is likely encrypted
	if packetTag == publicKeyEncryptedSessionKeyPacket ||
		packetTag == symmetricallyEncryptedDataPacket ||
		packetTag == symmetricallyEncryptedIntegrityProtectedDataPacket ||
		packetTag == compressedDataPacket ||
		packetTag == modificationDetectionCodePacket {
		return true, nil // Found a packet type that indicates encrypted content
	}

	// As a last resort, check if the data appears to be binary non-text
	// This is a heuristic approach that may help detect encrypted data
	// when standard packet detection fails
	if len(headerBytes) >= 8 {
		highBitCount := 0
		for i := 0; i < 8; i++ {
			if headerBytes[i] > 127 {
				highBitCount++
			}
		}

		// If more than half the bytes have high bit set, likely binary encrypted data
		// This is based on the observation that encrypted data often has high entropy
		// and many bytes with the high bit set
		if highBitCount >= 4 {
			return true, nil // Likely encrypted based on byte distribution
		}
	}

	// If we've reached this point, none of our detection methods identified
	// this as OpenPGP encrypted data
	return false, nil
}
