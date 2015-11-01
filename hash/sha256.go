// Package hash simplifies using Go's crypto package hashes for streaming.
package hash

import (
	"crypto"
	"crypto/sha256" // SHA256 will register itself
	"io"
	"log"
	"os"

	"github.com/traherom/gocrypt"
)

// Sha256Size holds the size of the hash output in bytes
var Sha256Size = sha256.Size

// Sha256 hashes the given stream and returns the result.
func Sha256(r io.Reader) (gocrypt.Hash, error) {
	h := crypto.SHA256.New()

	block := make([]byte, h.BlockSize())
	for {
		cnt, err := r.Read(block)
		h.Write(block[:cnt])

		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
	}

	return h.Sum(nil), nil
}

// Sha256File opens the given file and returns the SHA256 sum of it
func Sha256File(path string) (gocrypt.Hash, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	log.Println("summing", path)
	return Sha256(f)
}
