package arcsek

import (
	"crypto/sha1"
	"io/ioutil"
	"os"
	"testing"
)

func genKey(pw string) []byte {
	s := sha1.Sum([]byte(pw))
	return s[:16]
}

// Test we can delete the source of the enc reader
// on close

// Exists reports whether the named file or directory exists.
func fileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// Tests the Close method of the vault
func TestVaultReader_Close(t *testing.T) {
	tmpFile, err := ioutil.TempFile(".", "*.tar.gz")
	if err != nil {
		t.Fatal(err)
	}

	tmpPath := tmpFile.Name()

	// It doesn't matter if we have an enc reader or not.
	// We are testing delete on close
	v := VaultReader{nil, tmpPath}
	if !fileExists(tmpPath) {
		t.Fatal("The file was not created")
	}

	// The file exists at this point
	if err = v.Close(); err != nil {
		// Something happened
		t.Fatal(err)
	}

	// at this point the file should NOT exist
	if fileExists(tmpPath) {
		t.Fatalf("The file '%s' was not deleted on close", tmpPath)
	}

	t.Logf("The file %s was deleted", tmpPath)
}

// Test if the GCM can be created with a good or a bad key

func TestMakeGCMFromKey(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
		good bool
	}{
		{"Good 128 bit (16 byte) key", []byte("0123456789ABCDEF"), true},
		{"Bad key with len 4 bytes (16 bit)", []byte("1234"), false},
		{"Good 256 bit (32 byte) key",
			[]byte("0123456789ABCDEF0123456789ABCDEF"), true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := createAESGCMFromKey(tc.key)
			if (tc.good && err != nil) || (!tc.good && err == nil) {
				t.Fatal("Error not corresponing to key")
			}
		})
	}
}
