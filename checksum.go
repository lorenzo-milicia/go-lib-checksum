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
	stringHash, err := computeHash(hashFunction, r)
	if err != nil {
		return false, err
	}

	if stringHash == checksum {
		return true, nil
	}

	return false, nil
}

func Hash(r io.Reader, hashFunction crypto.Hash) (string, error) {
	return computeHash(hashFunction, r)
}

func computeHash(hashFunction crypto.Hash, r io.Reader) (string, error) {
	if !hashFunction.Available() {
		return "", errors.New(fmt.Sprintf("Hash function %v not implemented", hashFunction.String()))
	}
	hash := hashFunction.New()
	if _, err := io.Copy(hash, r); err != nil {
		return "", err
	}

	stringHash := hex.EncodeToString(hash.Sum(nil))
	return stringHash, nil
}
