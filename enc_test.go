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
	v := VaultReader{nil, tmpFile}
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

type vaultTC struct {
	name  string
	files []string
	key   []byte
	good  bool
}

func testMakeVaultGood(t *testing.T, tc vaultTC) {
	if _, err := NewVaultReader(tc.files, tc.key); err != nil {
		t.Fatal("Error should be nil in a good test case. Instead got ", err)
	}
}

func testMakeVaultBad(t *testing.T, tc vaultTC) {
	if _, err := NewVaultReader(tc.files, tc.key); err == nil {
		t.Fatal("Error should not be nil in a bad test case")
	}
}

func TestCreateVaultReader(t *testing.T) {
	goodFiles, _ := lsRecursive("testing-files/in")
	tests := []vaultTC{
		{
			"Good files good key",
			goodFiles,
			genKey("password123"),
			true,
		},
		{
			"Good files bad key",
			goodFiles,
			[]byte("123"),
			false,
		},
		{
			"Bad files good key",
			[]string{"imaginary", "files"},
			genKey("123"),
			false,
		},
	}
	for _, test := range tests {
		// If the test case is good test a good result,
		// otherwise test a bad result
		t.Run(test.name, func(t *testing.T) {
			if test.good {
				// Everything is good and test it as such
				testMakeVaultGood(t, test)
			} else {
				// Something is bad and is supposed to fail
				testMakeVaultBad(t, test)
			}
		})
	}
}
