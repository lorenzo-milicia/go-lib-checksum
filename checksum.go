package checksum

import (
	"crypto"
	_ "crypto/md5"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/hex"
)

func Checksum(b []byte, checksum string, algorithm crypto.Hash) bool {
	hash := algorithm.New()

	hash.Write(b)

	stringHash := hex.EncodeToString(hash.Sum(nil))

	if stringHash == checksum {
		return true
	}

	return false
}
