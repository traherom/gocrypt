// Package hash simplifies using Go's crypto package hashes for streaming.
package hash

import (
	"crypto"
	"crypto/sha256" // SHA256 will register itself
	"io"

	"github.com/traherom/gocrypt"
)

// Size of the hash output in bytes
var Sha256Size = sha256.Size

// Sha256 hashes the given stream and returns the result.
func Sha256(r io.Reader) (gocrypt.Hash, error) {
	h := crypto.SHA256.New()

	block := make([]byte, h.BlockSize())
	for {
		cnt, err := r.Read(block)
		h.Sum(block[:cnt])

		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
	}

	return h.Sum(nil), nil
}
