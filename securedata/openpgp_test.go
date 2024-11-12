package securedata

import (
	"bufio"
	"bytes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"os"
	"testing"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

func TestNewPGPSecureHandler(t *testing.T) {
	keys := GenerateTestKeys(t)
	privKey, pubKey := keys[0], keys[1]
	handler, err := NewPGPSecureHandler(WithPrivateKey(privKey), WithPublicKey(pubKey))
	require.NoError(t, err)
	require.NotNil(t, handler)
	assert.NotNil(t, handler.pgpHandle)
	assert.Equal(t, privKey, handler.privKey)
	assert.Equal(t, pubKey, handler.pubKey)
}

func TestWithPublicKeyPath(t *testing.T) {
	keys := GenerateTestKeys(t)
	pubKey := keys[1]

	tmpFile := createTempFile(t, pubKey)
	defer os.Remove(tmpFile.Name())

	handler, err := NewPGPSecureHandler(WithPublicKeyPath(tmpFile.Name()))
	require.NoError(t, err)
	require.NotNil(t, handler)
	assert.Equal(t, pubKey.GetFingerprint(), handler.pubKey.GetFingerprint())
}

func TestGpgKeys(t *testing.T) {
	pubkeyPath := "testdata/pubkey.asc"
	privkeyPath := "testdata/privkey.asc"

	handler, err := NewPGPSecureHandler(WithPublicKeyPath(pubkeyPath), WithPrivateKeyPath(privkeyPath, "password123"))
	require.NoError(t, err)
	require.NotNil(t, handler)

	var buf bytes.Buffer
	writer := createWriter(t, handler, &buf)
	writeData(t, writer, "test data")

	reader := createReader(t, handler, &buf)
	decryptedData := readData(t, reader)
	require.Equal(t, "test data", string(decryptedData))
}

func TestWithPrivateKeyPath(t *testing.T) {
	keys := GenerateTestKeys(t)
	privKey := keys[0]
	tests := []struct {
		name       string
		privateKey *crypto.Key
		passphrase string
	}{
		{"with passphrase", privKey, "testpassphrase"},
		{"without passphrase", privKey, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privKey := lockKeyIfNeeded(t, tt.privateKey, tt.passphrase)
			tmpFile := createTempFile(t, privKey)
			defer os.Remove(tmpFile.Name())

			handler, err := NewPGPSecureHandler(WithPrivateKeyPath(tmpFile.Name(), tt.passphrase))
			require.NoError(t, err)
			require.NotNil(t, handler)
			assert.Equal(t, privKey.GetFingerprint(), handler.privKey.GetFingerprint())
		})
	}
}

func TestPGPSecureHandler_Writer(t *testing.T) {
	keys := GenerateTestKeys(t)
	privKey, pubKey := keys[0], keys[1]
	handler, err := NewPGPSecureHandler(WithPrivateKey(privKey), WithPublicKey(pubKey))
	require.NoError(t, err)
	require.NotNil(t, handler)

	var buf bytes.Buffer
	writer := createWriter(t, handler, &buf)
	writeData(t, writer, "test data")

	require.NotEmpty(t, buf.Bytes())
}

func TestPGPSecureHandler_Reader(t *testing.T) {
	keys := GenerateTestKeys(t)
	aliceKeyPriv, aliceKeyPub := keys[0], keys[1]
	bobKeyPriv, bobKeyPub := keys[2], keys[3]
	chadKeyPriv := keys[4]
	tests := []struct {
		name           string
		senderPrivKey  *crypto.Key
		receiverPubKey *crypto.Key
		readerPrivKey  *crypto.Key
		readerPubKey   *crypto.Key
		wantErr        bool
		wantReadErr    bool
	}{
		{"alice to bob, bob reads", aliceKeyPriv, bobKeyPub, bobKeyPriv, aliceKeyPub, false, false},
		{"alice to bob, chad reads", aliceKeyPriv, bobKeyPub, chadKeyPriv, aliceKeyPub, true, true},
		{"chad impersonates alice to bob, bob reads", chadKeyPriv, bobKeyPub, bobKeyPriv, aliceKeyPub, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sendHandler := createHandler(t, tt.senderPrivKey, tt.receiverPubKey)
			var buf bytes.Buffer
			writer := createWriter(t, sendHandler, &buf)
			writeData(t, writer, "test data")

			readHandler := createHandler(t, tt.readerPrivKey, tt.readerPubKey)
			reader, err := readHandler.Reader(&buf)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			decryptedData, err := io.ReadAll(reader)

			if tt.wantReadErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, "test data", string(decryptedData))
			}
		})
	}
}

func TestIsRawEncrypted(t *testing.T) {
	keys := GenerateTestKeys(t)
	privKey, pubKey := keys[0], keys[1]
	handler, err := NewPGPSecureHandler(WithPrivateKey(privKey), WithPublicKey(pubKey))
	require.NoError(t, err)
	require.NotNil(t, handler)

	var buf bytes.Buffer
	writer := createWriter(t, handler, &buf)
	writeData(t, writer, "test data")

	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"empty data", []byte{}, false},
		{"encrypted data", buf.Bytes(), true},
		{"unencrypted data", []byte("test data"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bufio.NewReader(bytes.NewReader(tt.data))
			ok, err := IsRawEncrypted(reader)
			require.NoError(t, err)
			assert.Equal(t, tt.want, ok)
		})
	}
}

func createTempFile(t *testing.T, key *crypto.Key) *os.File {
	keyData, err := key.Armor()
	require.NoError(t, err)
	tmpFile, err := os.CreateTemp("", "*.asc")
	require.NoError(t, err)
	_, err = tmpFile.Write([]byte(keyData))
	require.NoError(t, err)
	require.NoError(t, tmpFile.Close())
	return tmpFile
}

func lockKeyIfNeeded(t *testing.T, key *crypto.Key, passphrase string) *crypto.Key {
	if passphrase == "" {
		return key
	}
	pgp := crypto.PGP()
	lockedKey, err := pgp.LockKey(key, []byte(passphrase))
	require.NoError(t, err)
	return lockedKey
}

func createHandler(t *testing.T, privKey, pubKey *crypto.Key) *OpenPGPSecureHandler {
	handler, err := NewPGPSecureHandler(WithPrivateKey(privKey), WithPublicKey(pubKey))
	require.NoError(t, err)
	require.NotNil(t, handler)
	return handler
}

func createWriter(t *testing.T, handler *OpenPGPSecureHandler, buf *bytes.Buffer) io.WriteCloser {
	writer, err := handler.Writer(buf)
	require.NoError(t, err)
	return writer
}

func writeData(t *testing.T, writer io.WriteCloser, data string) {
	_, err := writer.Write([]byte(data))
	require.NoError(t, err)
	require.NoError(t, writer.Close())
}

func createReader(t *testing.T, handler *OpenPGPSecureHandler, buf *bytes.Buffer) io.Reader {
	reader, err := handler.Reader(buf)
	require.NoError(t, err)
	return reader
}

func readData(t *testing.T, reader io.Reader) []byte {
	data, err := io.ReadAll(reader)
	require.NoError(t, err)
	return data
}
