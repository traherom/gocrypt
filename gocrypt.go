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
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
)

// Hash holds a cryptographic hash
type Hash []byte

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
	Msg   string
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
	return BytesToB64([]byte(*k))
}

// KeyFromString converts a base64-encoded string into a Key
func KeyFromString(str string) (key Key, err error) {
	return BytesFromB64(str)
}

// IsKeyComboEqual returns true if the keys in the given KeyCombos contain
// the same bytes.
func IsKeyComboEqual(a, b KeyCombo) bool {
	return bytes.Equal(a.CryptoKey, b.CryptoKey) && bytes.Equal(a.AuthKey, b.AuthKey)
}

// Uint64ToBytes returns the bytes of given uint64 in BigEndian format
func Uint64ToBytes(u uint64) []byte {
	bytes := make([]byte, 8)
	binary.BigEndian.PutUint64(bytes, u)
	return bytes
}

// BytesToUint64 takes the given bytes, in BigEndian format, and converts them to
// the corresponding uint64
func BytesToUint64(b []byte) uint64 {
	return binary.BigEndian.Uint64(b)
}

// BytesToB64 returns the given []byte into a base64-encoded string
func BytesToB64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// BytesFromB64 converts a base64-encoded string into a []byte
func BytesFromB64(str string) (b []byte, err error) {
	b, err = base64.StdEncoding.DecodeString(str)
	if err != nil {
		return nil, err
	}

	return
}
