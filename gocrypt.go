// Package gocrypt is designed to simplify the use of
// Golang's default crypto package. For example, the first
// version of this repo includes AES helper functions that
// work with io.Readers and io.Writers, rather than []byte
// arrays directly. This has the benefit of allowing files
// to be used directly, rather than having to either load
// the entire file into RAM.
package gocrypt

import (
	"bytes"
	"fmt"
	"crypto/rand"
	"encoding/base64"
)

// Key used for encryption
type Key []byte

// IV represents an initialization vector for encryption
type IV []byte

// KeyCombo combines a crypto and authentication key for ease of handling
type KeyCombo struct {
	CryptoKey Key
	AuthKey   Key
}

// ErrEncryption is any encryption-related error
type ErrEncryption struct {
	Msg string
	Inner error
}

func (e *ErrEncryption) Error() string {
	if e.Inner == nil {
		return fmt.Sprintf("encryption error: %v", e.Msg)
	}

	return fmt.Sprintf("encryption error: %v: %v", e.Msg, e.Inner)
}

// SecureBytes generates a new random, cryptographically secure block of bytes.
// Suitable for use with a key generator, IV, etc.
func SecureBytes(length int) ([]byte, error) {
	block := make([]byte, length)
	_, err := rand.Read(block)
	if err != nil {
		return nil, err
	}

	return block, nil
}

// Converts a key into a Base64 string, rather than just the straight bytes
func (k *Key) String() string {
	return base64.StdEncoding.EncodeToString([]byte(*k))
}

// KeyFromString converts a base64-encoded string into a Key
func KeyFromString(str string) (key Key, err error) {
	key, err = base64.StdEncoding.DecodeString(str)
	if err != nil {
		return nil, err
	}

	return
}

// IsKeyComboEqual returns true if the keys in the given KeyCombos contain
// the same bytes.
func IsKeyComboEqual(a, b KeyCombo) bool {
	return bytes.Equal(a.CryptoKey, b.CryptoKey) && bytes.Equal(a.AuthKey, b.AuthKey)
}
