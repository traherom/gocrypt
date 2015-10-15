package aes

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/traherom/gocrypt"
	"github.com/traherom/memstream"
)

var keys = &gocrypt.KeyCombo{
	gocrypt.Key{0xd3, 0x51, 0x87, 0x67, 0xad, 0xe9, 0x28, 0x33, 0x31, 0xc5, 0x26, 0x64, 0x8b, 0x79, 0xc7, 0x1f},
	gocrypt.Key{0xa7, 0x73, 0xa8, 0xff, 0x8c, 0xdf, 0x63, 0xd3, 0xcd, 0x1d, 0x0, 0x5c, 0x80, 0x1b, 0x20, 0x60},
}
var originals = [][]byte{[]byte("a short test"),
	[]byte("exactly one 1234"),
	[]byte("exactly two 1234 exactly two 123"),
	[]byte("this is a very long test case, certainly more than a single block"),
	[]byte("this is a very long test case, certainly more than a single block this is a very long test case, certainly more than a single block"),
	[]byte{},
}

// TestEncryptDecrypt tests if basic encrypt->decryption operation works correctly,
// producing the same bytes after decryption as the original
func TestEncryptDecrypt(t *testing.T) {
	for _, orig := range originals {
		//fmt.Printf("Encrypt/decrypt test %v: %v byte original\n", testNum, len(orig))

		// Encrypt
		encrypted, err := encryptExample(orig)
		if err != nil {
			t.Errorf("Encryption failed: %v", err)
			return
		}

		// Decrypt
		decrypted, err := decryptExample(encrypted)
		if err != nil {
			t.Errorf("Decryption failed: %v", err)
			return
		}

		if !bytes.Equal(orig, decrypted) {
			t.Error("Decrypted bytes do not match original")
			return
		}
	}
}

// TestDecryptModified tests if the decryption function correctly rejects
// altered originals, no matter where that alteration occurs
func TestDecryptModified(t *testing.T) {
	for _, orig := range originals {
		// Encrypt
		encrypted, err := encryptExample(orig)
		modified := make([]byte, len(encrypted))

		for modByte := 0; modByte < len(encrypted); modByte++ {
			//fmt.Printf("Mod test %v: changing byte %v of %v\n", testNum, modByte, len(encrypted))

			// Modify
			copy(modified, encrypted)
			modified[modByte]++

			// Decrypt
			_, err = decryptExample(modified)
			if err == nil {
				t.Errorf("Decryption did NOT fail like it should: %v", err)
				return
			}
		}
	}
}

// TestEncryptingFromMiddle tests that Encrypting when the source is NOT
// at the beginning of the stream works properly
func TestEncryptingFromMiddle(t *testing.T) {
	actualBytes := []byte("abcdefghijklmnopqrstuvwxyz")
	actualStart := 10

	orig := memstream.NewCapacity(30)
	orig.Write(actualBytes)

	// Jump part way in and encrypt
	orig.Seek(int64(actualStart), 0)
	encrypted := memstream.NewCapacity(50)
	_, _, err := Encrypt(orig, encrypted, keys)
	if err != nil {
		t.Errorf("Unable to encrypt: %v", err)
		return
	}

	// Decrypt
	encrypted.Seek(0, 0)
	decrypted := memstream.NewCapacity(30)
	_, _, err = Decrypt(encrypted, decrypted, keys)
	if err != nil {
		t.Errorf("Unable to decrypt: %v", err)
		return
	}

	if !bytes.Equal(actualBytes[actualStart:], decrypted.Bytes()) {
		t.Errorf("Decrypted bytes (%v) do not match original (%v)", decrypted.Bytes(), actualBytes)
		fmt.Println(decrypted.Bytes())
		fmt.Println(actualBytes[actualStart:])
		return
	}
}

func encryptExample(orig []byte) ([]byte, error) {
	var encryptionBuff bytes.Buffer
	_, _, err := Encrypt(bytes.NewReader(orig), &encryptionBuff, keys)
	if err != nil {
		return nil, err
	}

	return encryptionBuff.Bytes(), nil
}

func decryptExample(encrypted []byte) ([]byte, error) {
	var decryptBuff bytes.Buffer
	_, _, err := Decrypt(bytes.NewReader(encrypted), &decryptBuff, keys)
	if err != nil {
		return nil, err
	}

	return decryptBuff.Bytes(), nil
}
