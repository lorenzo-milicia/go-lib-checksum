package checksum

import (
	"crypto"
	_ "crypto/md5"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

func Validate(r io.Reader, checksum string, hashFunction crypto.Hash) (bool, error) {
	if !hashFunction.Available() {
		return false, errors.New(fmt.Sprintf("Hash function %v not implemented", hashFunction.String()))
	}

	hash := hashFunction.New()
	if _, err := io.Copy(hash, r); err != nil {
		return false, err
	}

	stringHash := hex.EncodeToString(hash.Sum(nil))

	if stringHash == checksum {
		return true, nil
	}

	return false, nil
}
