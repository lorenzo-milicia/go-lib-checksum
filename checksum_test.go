package checksum

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"testing"
)

func TestValidChecksum(t *testing.T) {
	var testString = "This is the string to test"
	tests := []struct {
		hashFunction crypto.Hash
	}{
		{crypto.SHA1},
		{crypto.SHA256},
		{crypto.SHA512},
		{crypto.MD5},
		{crypto.SHA224},
		{crypto.SHA384},
		{crypto.SHA512_224},
		{crypto.SHA512_256},
	}
	for _, test := range tests {
		t.Run(test.hashFunction.String(), func(t *testing.T) {
			r := bytes.NewBufferString(testString)
			var hash = test.hashFunction.New()
			hash.Write([]byte(testString))
			var checksum = hex.EncodeToString(hash.Sum(nil))
			isValid, err := Validate(r, checksum, test.hashFunction)
			if err != nil {
				t.Fatalf("Expected valid, got error %v", err)
			}
			if !isValid {
				t.Fatal("Expected valid")
			}
		})
	}
}
func TestInvalidChecksum(t *testing.T) {
	var testString = "This is the string to test"
	tests := []struct {
		hashFunction crypto.Hash
	}{
		{crypto.SHA1},
		{crypto.SHA256},
		{crypto.SHA512},
		{crypto.MD5},
		{crypto.SHA224},
		{crypto.SHA384},
		{crypto.SHA512_224},
		{crypto.SHA512_256},
	}
	for _, test := range tests {
		t.Run(test.hashFunction.String(), func(t *testing.T) {
			invalidChecksum := "Invalid checksum"
			r := bytes.NewBufferString(testString)
			isValid, err := Validate(r, invalidChecksum, test.hashFunction)
			if err != nil {
				t.Fatalf("Expected invalid, got error %v", err)
			}
			if isValid {
				t.Fatal("Expected invalid")
			}
		})
	}
}

func TestNotAvailableChecksum(t *testing.T) {
	var testString = "This is the string to test"
	tests := []struct {
		hashFunction crypto.Hash
	}{
		{crypto.MD4},
		{crypto.MD5SHA1},
		{crypto.RIPEMD160},
		{crypto.SHA3_224},
		{crypto.SHA3_256},
		{crypto.SHA3_384},
		{crypto.SHA3_512},
		{crypto.BLAKE2s_256},
		{crypto.BLAKE2b_256},
		{crypto.BLAKE2b_384},
		{crypto.BLAKE2b_512},
	}
	for _, test := range tests {
		t.Run(test.hashFunction.String(), func(t *testing.T) {
			checksum := "Any checksum"
			r := bytes.NewBufferString(testString)
			_, err := Validate(r, checksum, test.hashFunction)
			if err == nil {
				t.Fatal("Expected error")
			}
		})
	}
}

func TestValidHash(t *testing.T) {
	var testString = "This is the string to test"
	tests := []struct {
		hashFunction crypto.Hash
	}{
		{crypto.SHA1},
		{crypto.SHA256},
		{crypto.SHA512},
		{crypto.MD5},
		{crypto.SHA224},
		{crypto.SHA384},
		{crypto.SHA512_224},
		{crypto.SHA512_256},
	}
	for _, test := range tests {
		t.Run(test.hashFunction.String(), func(t *testing.T) {
			r := bytes.NewBufferString(testString)
			var hash = test.hashFunction.New()
			hash.Write([]byte(testString))
			_, err := Hash(r, test.hashFunction)
			if err != nil {
				t.Fatalf("Expected valid, got error %v", err)
			}
		})
	}
}

func TestNotAvailableHash(t *testing.T) {
	var testString = "This is the string to test"
	tests := []struct {
		hashFunction crypto.Hash
	}{
		{crypto.MD4},
		{crypto.MD5SHA1},
		{crypto.RIPEMD160},
		{crypto.SHA3_224},
		{crypto.SHA3_256},
		{crypto.SHA3_384},
		{crypto.SHA3_512},
		{crypto.BLAKE2s_256},
		{crypto.BLAKE2b_256},
		{crypto.BLAKE2b_384},
		{crypto.BLAKE2b_512},
	}
	for _, test := range tests {
		t.Run(test.hashFunction.String(), func(t *testing.T) {
			r := bytes.NewBufferString(testString)
			_, err := Hash(r, test.hashFunction)
			if err == nil {
				t.Fatal("Expected error")
			}
		})
	}
}
