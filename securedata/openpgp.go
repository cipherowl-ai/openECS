package securedata

import (
	"bufio"
	"errors"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
	"io"
	"os"
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

// IsRawEncrypted checks if the data is encrypted.
func IsRawEncrypted(reader *bufio.Reader) (bool, error) {
	// Define packet tags for asymmetric encryption detection
	const (
		publicKeyEncryptedSessionKeyPacket = 1 // Tag 1
		symmetricallyEncryptedDataPacket   = 9 // Tag 9
		compressedDataPacket               = 8 // Tag 8 (often used in encrypted messages)
		onePassSignaturePacket             = 4 // Tag 4 (used in signed and encrypted messages)
		signaturePacket                    = 2 // Tag 2 (digital signatures)
	)

	// Peek at the first 10 bytes to check for packet types
	// Attempt to peek at the first 20 bytes
	headerBytes, err := reader.Peek(20)
	if err != nil {
		if err != io.EOF {
			return false, err // An unexpected error occurred
		}
		// Handle cases where the file is smaller than 20 bytes (EOF reached)
		headerBytes = headerBytes[:len(headerBytes)] // Use available bytes
	}

	// Iterate over the peeked bytes to find packet tags related to encryption
	for _, b := range headerBytes {
		packetTag := b & 0x3F // Extract packet tag from each byte
		if packetTag == publicKeyEncryptedSessionKeyPacket ||
			packetTag == symmetricallyEncryptedDataPacket ||
			packetTag == compressedDataPacket ||
			packetTag == onePassSignaturePacket ||
			packetTag == signaturePacket {
			return true, nil
		}
	}

	return false, nil
}
