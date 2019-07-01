package main

import (
	"github.com/eacp/arcsek"
	"io"
	"os"
)

// Write te content of an encrypted vault.
// Take the encrypted reader and write it's
// nonce to a file so it can be loaded later
func writeEncToFile(vr arcsek.VaultReader, outPath string) error {
	file, err := os.Create(outPath)
	if err != nil {
		return err
	}

	//Write the nonce first
	if _, err = file.Write(vr.Nonce); err != nil {
		return err
	}

	// Then we can read the encrypted content normally and
	// use io copy to append it to the file.
	// If there is an error we return it
	_, err = io.Copy(file, vr)

	return err
}
