package arcsek

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"io/ioutil"
	"os"
)

// A method to adda file to a tar.gz
func addFileToTar(filePath string, tarWriter *tar.Writer) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return err
	}

	header := &tar.Header{
		Name:    filePath,
		Size:    stat.Size(),
		Mode:    int64(stat.Mode()),
		ModTime: stat.ModTime(),
	}

	err = tarWriter.WriteHeader(header)
	if err != nil {
		return err
	}

	_, err = io.Copy(tarWriter, file)
	if err != nil {
		return err
	}

	return nil
}

// Create a temporary .tar.gz file in disk and return its path
func createTemporaryTarGz(files []string) (string, error) {
	// Create the temporary file to store the .tar.gz
	tmp, err := ioutil.TempFile("", "*.tar.gz")
	if err != nil {
		return "", err
	}
	defer tmp.Close()

	gzw := gzip.NewWriter(tmp)
	defer gzw.Close()

	tw := tar.NewWriter(gzw)
	defer tw.Close()

	// add each file to the .tar.gz
	for _, file := range files {
		// Add each file to the .tar.gz
		if err = addFileToTar(file, tw); err != nil {
			return "", err
		}
	}

	// Everything is on the tar.
	return tmp.Name(), nil
}
