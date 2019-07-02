package arcsek

import (
	"archive/tar"
	"compress/gzip"
	"io"

	"github.com/secure-io/sio-go"
)

/*
This package deals with the decryption and
reconstruction of encrypted and decrypted
.tar.gz streams that can be used to create
new files or to respond to http requests
*/

// Uses a decrypted reader to construct a
// .tar.gz reader that uses the dec reader
// to get the data. It assumes the reader
// has been decrypted and authenticated
func tarReader(dec *sio.DecReader) (*tar.Reader, error) {
	gr, err := gzip.NewReader(dec)
	if err != nil {
		return nil, err
	}

	return tar.NewReader(gr), nil
}

// NewTarReaderNonce receives an encrypted stream
// of data that starts with a nonce and a key to
// decrypt and authenticate it. Then it uses it to
// create a tar.gz reader from which you can exract files
func NewTarReaderNonce(enc io.Reader, key []byte) (*tar.Reader, error) {
	// We must create a decrypted reader from enc.
	dr, err := DecryptVault(enc, key)
	if err != nil {
		return nil, err
	}

	return tarReader(dr)
}
