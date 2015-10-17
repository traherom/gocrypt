package aes

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	_ "crypto/sha256" // SHA256 needed for HMAC
	"fmt"
	"io"

	"github.com/traherom/gocrypt"
)

// ErrLength represents an issue with input length during decryption
var ErrLength = &gocrypt.ErrEncryption{Msg: "Ciphertext not complete, length insufficient"}

// ErrHmac indicates that the calculated HMAC did not match the attached
// HMAC during decryption.
var ErrHmac = &gocrypt.ErrEncryption{Msg: "HMACs do not match"}

// gocrypt.KeyLength is the length in bytes of the gocrypt.Keys expected by gocrypt/aes's functions
var KeyLength = aes.BlockSize

// NewKey generates a new random, cryptographically secure gocrypt.Key for use with
// Encrypt and Decrypt.
func NewKey() (gocrypt.Key, error) {
	return gocrypt.SecureBytes(KeyLength)
}

// newIV generates a new, cryptographically secure IV for use with
func newIV() (gocrypt.IV, error) {
	return gocrypt.SecureBytes(aes.BlockSize)
}

// NewKeyCombo produces a crypto/auth gocrypt.Key set with new gocrypt.Keys. If the gocrypt.Keys are
// already know (ie, decrypting), produce the gocrypt.gocrypt.KeyCombo directly
func NewKeyCombo() (*gocrypt.KeyCombo, error) {
	c, err := NewKey()
	if err != nil {
		return nil, err
	}

	a, err := NewKey()
	if err != nil {
		return nil, err
	}

	return &gocrypt.KeyCombo{CryptoKey: c, AuthKey: a}, nil
}

// Encrypt encrypts the given input stream into the output using AES-OFB with
// encrypt-then-HMAC. Cipher text includes all data (except the gocrypt.Key) needed to
// decrypt the stream via |Decrypt|.
//
// Encrypts the entire plaintext, starting from the current position. To limit
// reading, use |EncryptLength|.
func Encrypt(plaintext io.ReadSeeker, ciphertext io.Writer, keys *gocrypt.KeyCombo) (totalRead int64, writtenCnt int64, err error) {
	// Determine length of input
	plainStartPos, err := plaintext.Seek(0, 1)
	if err != nil {
		return 0, 0, err
	}

	plainLen, err := plaintext.Seek(0, 2)
	if err != nil {
		// Try to return to where we were. If we fail, we can't do anything with
		// the error anyway. Return the original one
		finalPos, _ := plaintext.Seek(plainStartPos, 0)
		return finalPos - plainStartPos, 0, err
	}

	plainLen = plainLen - plainStartPos

	// TODO handle case where plainStartPos > max int. Probably need to loop out to it
	_, err = plaintext.Seek(plainStartPos, 0)
	if err != nil {
		return 0, 0, err
	}

	return EncryptLength(plaintext, plainLen, ciphertext, keys)
}

// EncryptLength encrypts the given input stream into the output using AES-OFB with
// encrypt-then-HMAC. Cipher text includes all data (except the gocrypt.Key) needed to
// decrypt the stream via |Decrypt|.
//
// Reads plainLen characters from the plaintext. If less than plainLen is available,
// EncryptLength returns an error.
func EncryptLength(plaintext io.Reader, plainLen int64, ciphertext io.Writer, keys *gocrypt.KeyCombo) (totalRead int64, writtenCnt int64, err error) {
	// Init cipher and hash
	blockCipher, err := aes.NewCipher(keys.CryptoKey)
	if err != nil {
		return 0, 0, err
	}

	iv, err := newIV()
	if err != nil {
		return 0, 0, err
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
		return 0, writtenCnt, err
	}

	// IV
	hash.Write(iv)
	c, err = ciphertext.Write(iv)
	writtenCnt += int64(c)
	if err != nil {
		return 0, writtenCnt, err
	}

	// Encrypted data
	readBlock := make([]byte, blockCipher.BlockSize())
	writeBlock := make([]byte, blockCipher.BlockSize())
	for {
		// If we reach the EOF during this read, we still need to write out
		// the last bit of data, so don't terminate immediately.
		readCount, err := plaintext.Read(readBlock)
		totalRead += int64(readCount)
		if err != nil && err != io.EOF {
			return totalRead, writtenCnt, err
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
			return totalRead, writtenCnt, err
		}

		// Calc HMAC as we go along, avoiding a second pass
		hash.Write(writeBlock[:readCount])
	}

	// HMAC
	c, err = ciphertext.Write(hash.Sum(nil))
	writtenCnt += int64(c)
	if err != nil {
		return totalRead, writtenCnt, err
	}

	// Sanity checks
	if totalRead != plainLen {
		return totalRead, writtenCnt, fmt.Errorf("Only able to read %v bytes, expected %v", totalRead, plainLen)
	}
	if writtenCnt != totalLen {
		panic(fmt.Sprintf("Written count (%v) does not match calculated total length (%v). Encrypt is broken.", writtenCnt, totalLen))
	}

	return totalRead, writtenCnt, nil
}

// Decrypt decrypts the given input stream into the output using AES-GCM
func Decrypt(ciphertext io.Reader, plaintext io.Writer, keys *gocrypt.KeyCombo) (totalRead int64, writtenCnt int64, err error) {
	// Init hmac now, because we need to calculated it the entire way
	hash := hmac.New(crypto.SHA256.New, keys.AuthKey)

	// Decrypt, calculating hmac as we go to compare at the end
	// Format of input should be:
	// total length (8 bytes)
	// iv (16 bytes)
	// encrypted data (... bytes)
	// hmac ()
	lenAsBytes := make([]byte, 8)
	c, err := ciphertext.Read(lenAsBytes)
	totalRead += int64(c)
	if err != nil {
		return totalRead, 0, &gocrypt.ErrEncryption{"unable to read stream length", err}
	}
	if c != len(lenAsBytes) {
		return totalRead, 0, ErrLength
	}

	totalLen := bytesToInt64(lenAsBytes)
	hash.Write(lenAsBytes)

	// IV
	iv := make([]byte, aes.BlockSize)
	c, err = ciphertext.Read(iv)
	totalRead += int64(c)
	if err != nil {
		return totalRead, 0, &gocrypt.ErrEncryption{"unable to read IV", err}
	}
	if c != len(iv) {
		return totalRead, 0, ErrLength
	}

	hash.Write(iv)

	// Init cipher now that we have the iv
	blockCipher, err := aes.NewCipher(keys.CryptoKey)
	if err != nil {
		return totalRead, 0, &gocrypt.ErrEncryption{"unable to init cipher", err}
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
			return totalRead, writtenCnt, &gocrypt.ErrEncryption{"error reading content", err}
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
			return totalRead, writtenCnt, &gocrypt.ErrEncryption{"unable to write decrypted content", err}
		}
	}

	// Compare HMACs
	attachedHmac := make([]byte, hash.Size())
	c, err = ciphertext.Read(attachedHmac)
	totalRead += int64(c)
	if err != nil && err != io.EOF {
		return totalRead, writtenCnt, &gocrypt.ErrEncryption{"unable to read HMAC", err}
	}
	if c < len(attachedHmac) {
		return totalRead, writtenCnt, ErrLength
	}

	calcedHmac := hash.Sum(nil)

	if !hmac.Equal(calcedHmac, attachedHmac) {
		return totalRead, writtenCnt, ErrHmac
	}

	// Final safety check
	if totalRead < totalLen {
		return totalRead, writtenCnt, ErrLength
	}

	return totalRead, writtenCnt, nil
}

// calcCipherLength determines how long the cipher text will be for a given
// plaintext length in AES-OFB mode
func calcCipherLength(plainLen int64) int64 {
	// For AES-OFB, we're truncating immediately after we encrypt everything
	return plainLen
}

func int64ToBytes(u int64) []byte {
	return gocrypt.Uint64ToBytes(uint64(u))
}

func bytesToInt64(b []byte) int64 {
	return int64(gocrypt.BytesToUint64(b))
}
