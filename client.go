package relay

import (
	"crypto/sha256"
	"io"
	"os"
)

func HashFile(path string) ([]byte, error) {
	hasher := sha256.New()

	handle, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	if _, err = io.Copy(hasher, handle); err != nil {
		return nil, err
	}

	return hasher.Sum(nil), nil
}
