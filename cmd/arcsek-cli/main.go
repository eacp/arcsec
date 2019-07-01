package main

import (
	"crypto/sha1"
	"fmt"
	"github.com/eacp/arcsek"
	"log"
)

/*
Sample program to show the capabilities
of the library. It takes a directory and
creates an encrypted archive from it
*/

// Create a 128 key from an arbitrary size
// password
func makeKeyFromPass(pass string) []byte {
	s := sha1.Sum([]byte(pass))
	return s[:16]
}

func main() {
	paths := []string{"testfile1.txt", "testfile2.txt", "testfile3.txt", "testfile4.txt"}
	k := makeKeyFromPass("password123")
	vr, err := arcsek.NewVaultReader(paths, k)

	if err != nil {
		log.Fatal(err)
	}

	// create a file to put the stuff
	if err = writeEncToFile(*vr, "large.tar.gz.enc"); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("The nonce is: %x.\nThe file has been encrypted", vr.Nonce)
}
