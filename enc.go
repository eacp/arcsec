package arcsek

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"

	"github.com/secure-io/sio-go"
)

// VaultReader is amazing :D
//
// but also implements io.Closer by deleting the underlying
// temporal clean file.
// It also stores the nonce if you need to use it later
//
// It is important to close the vault in order to prevent
// the retrieval of the plain data from the temporal dir.
type VaultReader struct {
	*sio.EncReader
	tmpFile *os.File
	Nonce   []byte
}

// Close errases the underlying tempora
// file to prevent it's retrieval by an attacker
// and save disk space
func (v *VaultReader) Close() error {
	// We have to remove the file from the
	// disk. Once we do this we wont be able to
	// read from it again
	if err := v.tmpFile.Close(); err != nil {
		return err
	}
	return os.Remove(v.tmpFile.Name())
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

// NewVaultReader creates a new Vault reader by
// packaging the specified files and encrypted the archive
// with the specified key.
//
// It will use AES 128, 192 or 256 depending on the
// length of the key. If a key of different length is
// provided, it will return an error.
//
// It is important that you close this reader after you
// are done with it to delete any plain data
// that might be left
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

	ns := stream.NonceSize()

	nonce := make([]byte, ns)

	if _, err = io.ReadFull(rand.Reader, nonce[:ns]); err != nil {
		return nil, err
	}

	//fmt.Println(nonce)

	// Use that stream to make an enc reader according to sio docs
	er := stream.EncryptReader(tmpFile, nonce[:ns], nil)

	return &VaultReader{er, tmpFile, nonce}, nil
}

// Simplifies the creation of a stream by just asking for
// the key
func createStreamFromKey(key []byte) (*sio.Stream, error) {
	// We need a block cipher first
	AESGCM, err := createAESGCMFromKey(key)
	if err != nil {
		return nil, err
	}

	// With that we can create a Stream
	s := sio.NewStream(AESGCM, sio.BufSize)

	return s, nil
}

// DecryptVault receives an io.Reader that contains
// an encrypted content and it's nonce at the start
// of it.
//
// If the key is not 128, 192 or 256 bits
// long it will cause an error. If the data cannot be
// authenticated it will also return an error
func DecryptVault(er io.Reader, key []byte) (*sio.DecReader, error) {
	stream, err := createStreamFromKey(key)
	if err != nil {
		return nil, err
	}

	// We read the nonce from the er
	nonce, err := readNonce(er, stream.NonceSize())
	if err != nil {
		return nil, err
	}

	fmt.Printf("The nonce is: %x\n", nonce)
	// We use the key and the nonce to create a decrypted reader
	dr := stream.DecryptReader(er, nonce, nil)

	return dr, nil
}

// Gets the nonce from a reader containing encrypted data
func readNonce(er io.Reader, nonceSize int) ([]byte, error) {
	n := make([]byte, nonceSize)
	_, err := er.Read(n)
	return n, err
}
