package arcsek

import (
	"archive/tar"
	"compress/gzip"
	"io/ioutil"
	"testing"
)

// Test if the function can add existing files to a tar
// and generates errors when adding a file that does not
// exists
func TestAddFileToTarGz(t *testing.T) {
	testCases := []struct {
		path   string
		exists bool
	}{
		{"testing-files/in/existance/testfile1.txt", true},
		{"testing-files/in/existance/testfile2.txt", true},
		{"testing-files/in/existance/testfile2.txt", true},
		{"path/to/imaginary-file.txt", false},
		{"testing-files/in/existance/testfile4.txt", true},
		{"path/to/other/imaginary/file.txt", false},
	}

	// A temporary tar writer with a file as its backend
	// Create the temporary file to store the .tar.gz
	tmp, err := ioutil.TempFile("testing-files/out", "*.large.tar.gz")

	// Used .large so git ignores this file

	if err != nil {
		t.Fatal(err)
	}
	defer tmp.Close()

	gzw := gzip.NewWriter(tmp)
	defer gzw.Close()

	tw := tar.NewWriter(gzw)
	defer tw.Close()

	// For each tc it should succeed if the file exists, or
	// return an error if the file does not exist
	for _, tc := range testCases {
		// Try to adda file that does not exists
		err := addFileToTar(tc.path, tw)
		// If the file exists, it should be added and err == nil,
		// Otherwise, the error should should NOT be nil
		if (tc.exists && err != nil) || (!tc.exists && err == nil) {
			t.Fatal("The add function does not behave accordingly")
		}
	}
}

// Testing the whole function that packages the files
// in a temp dir
func testCreateTmpBadFiles(t *testing.T) {
	files := []string{
		"testing-files/in/existance/testfile1.txt",
		"testing-files/in/existance/testfile2.txt",
		"imaginary/file.txt",
	}

	if _, err := createTemporaryTarGz(files); err == nil {
		t.Fatal("There is at least one file that does not exists but is being added")
	}
}

func testCreateTmpGoodFiles(t *testing.T) {
	files := []string{
		"testing-files/in/existance/testfile1.txt",
		"testing-files/in/existance/testfile2.txt",
	}

	if tmpPath, err := createTemporaryTarGz(files); err != nil {
		t.Fatal("This files exist and there should be no error")
	} else {
		t.Logf("The tempral archive is located at: '%s'", tmpPath)
	}
}

// List all the files in test-files/in if they are not directories
func lsRecursive(rootDir string) ([]string, error) {
	// Allocate some space
	fis, err := ioutil.ReadDir("testing-files/in")
	if err != nil {
		return nil, err
	}

	ls := make([]string, 0, len(fis)+1)

	for _, fi := range fis {
		if !fi.IsDir() {
			ls = append(ls, "testing-files/in/"+fi.Name())
		}
	}

	return ls, nil
}

func TestCreateTempTarGz(t *testing.T) {
	t.Run("Bad files that should fail", testCreateTmpBadFiles)
	t.Run("Good files that should not fail", testCreateTmpGoodFiles)
}

func TestCreateFromDir(t *testing.T) {
	paths, err := lsRecursive("testing-files/in")
	if err != nil {
		t.Fail()
	}

	// Create a temporal tar using all the files present in the inputs
	if tmpPath, err := createTemporaryTarGz(paths); err != nil {
		t.Fatal("This files exist and there should be no error")
	} else {
		t.Logf("The tempral archive is located at: '%s'", tmpPath)
	}

}
