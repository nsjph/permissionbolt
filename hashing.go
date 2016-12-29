package permissionbolt

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"

	"io"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
)

// Hash the password with sha256 (the username is needed for salting)
func hashSha256(cookieSecret, username, password string) []byte {
	hasher := sha256.New()
	// Use the cookie secret as additional salt
	io.WriteString(hasher, password+cookieSecret+username)
	return hasher.Sum(nil)
}

// Hash the password with bcrypt
func hashBcrypt(password string) []byte {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		panic("Permissions: bcrypt password hashing unsuccessful")
	}
	return hash
}

// Hash the password with pbkdf2
func hashPbkdf2(salt, username, password string) []byte {
	saltBytes, err := hex.DecodeString(salt)
	if err != nil {
		return nil
	}

	return pbkdf2.Key([]byte(password), saltBytes, 10000, 32, sha256.New)
}

// Check if a given password(+username) is correct, for a given sha256 hash
func correctSha256(hash []byte, cookieSecret, username, password string) bool {
	comparisonHash := hashSha256(cookieSecret, username, password)
	// check that the lengths are equal before calling ConstantTimeCompare
	if len(hash) != len(comparisonHash) {
		return false
	}
	// prevents timing attack
	return subtle.ConstantTimeCompare(hash, comparisonHash) == 1
}

// Check if a given password is correct, for a given bcrypt hash
func correctBcrypt(hash []byte, password string) bool {
	// prevents timing attack
	return bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
}

func correctPbkdf2(hash []byte, salt, password string) bool {
	saltBytes, err := hex.DecodeString(salt)
	if err != nil {
		return false
	}

	switch bytes.Compare(hash, pbkdf2.Key([]byte(password), saltBytes, 10000, 32, sha256.New)) {
	case 0:
		return true
	case -1:
		return false
	default:
		return false
	}
}

// Check if the given hash is sha256 (when the alternative is only bcrypt)
func isSha256(hash []byte) bool {
	return len(hash) == 32
}
