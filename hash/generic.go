package hash

import (
	"hash"
	"io"

	"github.com/traherom/gocrypt"
)

// HashReader hashes the given reader with the specified hash,
// returning the final sum. This is done in blocks, so reading
// from large files or other out-of-memory sources should not
// cause memory issues.
func HashReader(h hash.Hash, r io.Reader) (gocrypt.Hash, error) {
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
