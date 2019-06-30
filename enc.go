package arcsek

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"os"

	"github.com/secure-io/sio-go"
)

// This type is composed of an encrypted reader
// but also implements io.Closer by deleting the underlying
// temporal clean file.
//
// It is important to close the vault in order to prevent
// the retrieval of the plain data from the temporal dir.
type VaultReader struct {
	*sio.EncReader
	tmpFilePath string
}

func (v *VaultReader) Close() error {
	// We have to remove the file from the
	// disk. Once we do this we wont be able to
	// read from it again
	return os.Remove(v.tmpFilePath)
}

// Create a GCM from the key
// This will fail if they key is bad.
//
// Separated for better test coverage
func createAESGCMFromKey(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}

// Package the specified files and
// encrypt the result. Then create a Vault Reader that can
// also be closed.
//
// It is important that you close this reader after you
// are done with it
func NewVaultReader(files []string, key []byte) (*VaultReader, error) {
	// Get a temporal path from which we will create an
	// encrypted reader
	tmpPath, err := createTemporaryTarGz(files)
	if err != nil {
		return nil, err
	}

	// Open that file in read mode and encrypt its reader
	tmpFile, err := os.Open(tmpPath)
	if err != nil {
		return nil, err
	}

	// Create an encrypted reader from that file
	gcm, err := createAESGCMFromKey(key)
	if err != nil {
		return nil, err
	}

	// We can now create a vault thanks to sio
	stream := sio.NewStream(gcm, sio.BufSize)

	nonce := make([]byte, 0, stream.NonceSize())

	if _, err = io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}

	// Use that stream to make an enc reader according to sio docs
	er := stream.EncryptReader(tmpFile, nonce, nil)

	return &VaultReader{er, tmpPath}, nil
}
