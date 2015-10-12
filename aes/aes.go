package aes

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

import _ "crypto/sha256" // SHA256 needed for HMAC

// Key used for encryption
type Key []byte

// IV represents an initialization vector for encryption
type IV []byte

// KeyCombo combines a crypto and authentication key for ease of handling
type KeyCombo struct {
	CryptoKey Key
	AuthKey   Key
}

// ErrLength represents an issue with input length during decryption
var ErrLength = errors.New("Ciphertext not complete, length insufficient")

// ErrHmac indicates that the calculated HMAC did not match the attached
// HMAC during decryption.
var ErrHmac = errors.New("HMACs do not match")

// NewKey generates a new random, cryptographically secure Key for use with
// Encrypt and Decrypt.
func NewKey() (Key, error) {
	key := make([]byte, aes.BlockSize)
	_, err := rand.Read(key)
	if err != nil {
		return Key(nil), err
	}

	return key, nil
}

// newIV generates a new, cryptographically secure IV for use with
func newIV() (IV, error) {
	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, err
	}

	return iv, nil
}

// NewKeyCombo produces a crypto/auth key set with new keys. If the keys are
// already know (ie, decrypting), produce the KeyCombo directly
func NewKeyCombo() (*KeyCombo, error) {
	c, err := NewKey()
	if err != nil {
		return nil, err
	}

	a, err := NewKey()
	if err != nil {
		return nil, err
	}

	return &KeyCombo{c, a}, nil
}

// Encrypt encrypts the given input stream into the output using AES-OFB with
// encrypt-then-HMAC. Cipher text includes all data (except the key) needed to
// decrypt the stream via |Decrypt|.
//
// Encrypts the entire plaintext, starting from the current position. To limit
// reading, use |EncryptLength|.
func Encrypt(plaintext io.ReadSeeker, ciphertext io.Writer, keys *KeyCombo) (writtenCnt int64, err error) {
	// Determine length of input
	plainStartPos, err := plaintext.Seek(0, 1)
	if err != nil {
		return 0, err
	}

	plainLen, err := plaintext.Seek(0, 2)
	if err != nil {
		return 0, err
	}

	// TODO handle case where plainStartPos > max int. Probably need to loop out to it
	_, err = plaintext.Seek(0, int(plainStartPos))
	if err != nil {
		return 0, err
	}

	return EncryptLength(plaintext, plainLen, ciphertext, keys)
}

// EncryptLength encrypts the given input stream into the output using AES-OFB with
// encrypt-then-HMAC. Cipher text includes all data (except the key) needed to
// decrypt the stream via |Decrypt|.
//
// Reads plainLen characters from the plaintext. If less than plainLen is available,
// EncryptLength returns an error.
func EncryptLength(plaintext io.Reader, plainLen int64, ciphertext io.Writer, keys *KeyCombo) (writtenCnt int64, err error) {
	// Init cipher and hash
	blockCipher, err := aes.NewCipher(keys.CryptoKey[:])
	if err != nil {
		return 0, err
	}

	iv, err := newIV()
	if err != nil {
		return 0, err
	}

	ofb := cipher.NewOFB(blockCipher, iv)
	hash := hmac.New(crypto.SHA256.New, keys.AuthKey[:])

	// Write out encrypted and auth'd text in the format
	// total length (8 bytes)
	// iv (16 bytes)
	// encrypted data (... bytes)
	// hmac ()
	var totalLen int64
	totalLen = int64(8) + int64(len(iv)) + calcCipherLength(plainLen) + int64(hash.Size())
	lenAsBytes := int64ToBytes(totalLen)

	hash.Write(lenAsBytes)
	c, err := ciphertext.Write(lenAsBytes)
	writtenCnt += int64(c)
	if err != nil {
		return writtenCnt, err
	}

	// IV
	hash.Write(iv)
	c, err = ciphertext.Write(iv)
	writtenCnt += int64(c)
	if err != nil {
		return writtenCnt, err
	}

	// Encrypted data
	readBlock := make([]byte, blockCipher.BlockSize())
	writeBlock := make([]byte, blockCipher.BlockSize())
	totalRead := int64(0)
	for {
		// If we reach the EOF during this read, we still need to write out
		// the last bit of data, so don't terminate immediately.
		readCount, err := plaintext.Read(readBlock)
		totalRead += int64(readCount)
		if err != nil && err != io.EOF {
			return writtenCnt, err
		}
		if readCount == 0 {
			break
		}

		// Terminate writing immediately after the last byte, dropping
		// any extra bytes. We may not write a full block for the last block,
		// as a result.
		ofb.XORKeyStream(writeBlock, readBlock[:readCount])
		c, err = ciphertext.Write(writeBlock[:readCount])
		writtenCnt += int64(c)
		if err != nil {
			return writtenCnt, err
		}

		// Calc HMAC as we go along, avoiding a second pass
		hash.Write(writeBlock[:readCount])
	}

	// HMAC
	c, err = ciphertext.Write(hash.Sum(nil))
	writtenCnt += int64(c)
	if err != nil {
		return writtenCnt, err
	}

	// Sanity checks
	if totalRead != plainLen {
		return writtenCnt, fmt.Errorf("Only able to read %v bytes, expected %v", totalRead, plainLen)
	}
	if writtenCnt != totalLen {
		panic(fmt.Sprintf("Written count (%v) does not match calculated total length (%v). Encrypt is broken.", writtenCnt, totalLen))
	}

	return writtenCnt, nil
}

// Decrypt decrypts the given input stream into the output using AES-GCM
func Decrypt(ciphertext io.Reader, plaintext io.Writer, keys *KeyCombo) (writtenCnt int64, err error) {
	// Init hmac now, because we need to calculated it the entire way
	hash := hmac.New(crypto.SHA256.New, keys.AuthKey[:])

	// Decrypt, calculating hmac as we go to compare at the end
	// Format of input should be:
	// total length (8 bytes)
	// iv (16 bytes)
	// encrypted data (... bytes)
	// hmac ()
	totalRead := int64(0)
	lenAsBytes := make([]byte, 8)
	c, err := ciphertext.Read(lenAsBytes)
	totalRead += int64(c)
	if err != nil {
		return 0, err
	}
	if c != len(lenAsBytes) {
		return 0, ErrLength
	}

	totalLen := bytesToInt64(lenAsBytes)
	hash.Write(lenAsBytes)

	// IV
	iv := make([]byte, aes.BlockSize)
	c, err = ciphertext.Read(iv)
	totalRead += int64(c)
	if err != nil {
		return 0, err
	}
	if c != len(iv) {
		return 0, ErrLength
	}

	hash.Write(iv)

	// Init cipher now that we have the iv
	blockCipher, err := aes.NewCipher(keys.CryptoKey[:])
	if err != nil {
		return 0, err
	}

	ofb := cipher.NewOFB(blockCipher, iv)

	// Decrypt data
	readBlock := make([]byte, aes.BlockSize)
	writeBlock := make([]byte, aes.BlockSize)
	for totalRead < totalLen-int64(hash.Size()) {
		// We need to limit the amount we read for the final block. Make sure
		// we leave just the HMAC at the end of the stream.
		maxRead := cap(readBlock)
		if totalLen-totalRead < int64(maxRead+hash.Size()) {
			maxRead = int(totalLen - int64(hash.Size()) - totalRead)
		}

		// If we reach the EOF during this read, we still need to write out
		// the last bit of data, so don't terminate immediately.
		readCount, err := ciphertext.Read(readBlock[:maxRead])
		totalRead += int64(readCount)
		if err != nil && err != io.EOF {
			return writtenCnt, err
		}
		if readCount == 0 {
			break
		}

		// Calc HMAC of encrypted data to compare to at the end
		hash.Write(readBlock[:readCount])

		// Decrypt
		ofb.XORKeyStream(writeBlock, readBlock[:readCount])
		c, err = plaintext.Write(writeBlock[:readCount])
		writtenCnt += int64(c)
		if err != nil {
			return writtenCnt, err
		}
	}

	// Compare HMACs
	attachedHmac := make([]byte, hash.Size())
	c, err = ciphertext.Read(attachedHmac)
	totalRead += int64(c)
	if err != nil && err != io.EOF {
		return writtenCnt, err
	}
	if c < len(attachedHmac) {
		return writtenCnt, ErrLength
	}

	calcedHmac := hash.Sum(nil)

	if !hmac.Equal(calcedHmac, attachedHmac) {
		return writtenCnt, ErrHmac
	}

	// Final safety check
	if totalRead < totalLen {
		return writtenCnt, ErrLength
	}

	return writtenCnt, nil
}

// calcCipherLength determines how long the cipher text will be for a given
// plaintext length in AES-OFB mode
func calcCipherLength(plainLen int64) int64 {
	// For AES-OFB, we're truncating immiately after we encrypt everything
	return plainLen
}

func int64ToBytes(u int64) []byte {
	bytes := make([]byte, 8)
	binary.BigEndian.PutUint64(bytes, uint64(u))
	return bytes
}

func bytesToInt64(b []byte) int64 {
	return int64(binary.BigEndian.Uint64(b))
}
