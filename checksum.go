package checksum

import (
	"crypto"
	_ "crypto/md5"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/hex"
	"io"
)

func Checksum(r io.Reader, checksum string, algorithm crypto.Hash) bool {
	hash := algorithm.New()
	if _, err := io.Copy(hash, r); err != nil {
		return false
	}
	stringHash := hex.EncodeToString(hash.Sum(nil))

	if stringHash == checksum {
		return true
	}

	return false
}
