// Package vaes128 implements variable AES128 encryption/decryption
package vaes128

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// Variable length AES128 (VAES128) key.
type Key struct {
	static_iv   []byte
	static_msgk []byte
}

// Create new VAES128 key with the given static parts.
// Static parts of key are to be used for encryption and decryption using VAES128 (len=0-16 for both).
// Random bytes will be prepended to fill full block if len is less than 16.
func New(static_iv string, static_msgk string) Key {
	var key Key
	key.Set(static_iv, static_msgk)
	return key
}

// Set static parts of key are to be used for encryption and decryption using VAES128 (len=0-16 for both).
// Random bytes will be prepended to fill full block if len is less than 16.
func (k *Key) Set(static_iv string, static_msgk string) {
	if len(static_iv) > aes.BlockSize {
		static_iv = static_iv[:aes.BlockSize]
	}
	if len(static_msgk) > aes.BlockSize {
		static_msgk = static_msgk[:aes.BlockSize]
	}

	k.static_iv = []byte(static_iv)
	k.static_msgk = []byte(static_msgk)
}

// Encrypt buf using VAES128
func (k Key) Encrypt(plain []byte) ([]byte, error) {
	rivLen := aes.BlockSize - len(k.static_iv)
	rmsgkLen := aes.BlockSize - len(k.static_msgk)

	// Generate full IV and message key
	iv := make([]byte, aes.BlockSize)
	rand.Read(iv[:rivLen])
	copy(iv[rivLen:], k.static_iv)

	msgk := make([]byte, aes.BlockSize)
	rand.Read(msgk[:rmsgkLen])
	copy(msgk[rmsgkLen:], k.static_msgk)

	// Create cipher and calculate required sizes for ciphertext
	block, err := aes.NewCipher(msgk)
	if err != nil {
		return nil, err
	}
	blocknum := len(plain)/aes.BlockSize + 1
	padnum := blocknum*aes.BlockSize - len(plain)

	// Pad the message
	if padnum == 0 {
		padnum = aes.BlockSize
	}
	pnum := byte(padnum)

	// Encrypt and prepend random part of IV and message key
	out := make([]byte, rivLen+rmsgkLen+len(plain)+padnum)
	copy(out, iv[:rivLen])
	copy(out[rivLen:], msgk[:rmsgkLen])

	start := rivLen + rmsgkLen
	copy(out[start:], plain)
	for i := start + len(plain); i < len(out); i++ {
		out[i] = pnum
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(out[start:], out[start:])
	return out, nil
}

// Encrypt buf using VAES128 and convert the result to hex string
func (k Key) EncryptHstr(plain []byte) (string, error) {
	ciph, err := k.Encrypt(plain)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(ciph), nil
}

// Decrypt cipherbuf using VAES128
func (k Key) Decrypt(ciph []byte) ([]byte, error) {
	rivLen := aes.BlockSize - len(k.static_iv)
	rmsgkLen := aes.BlockSize - len(k.static_msgk)
	paddedLen := len(ciph) - rivLen - rmsgkLen

	if paddedLen%aes.BlockSize != 0 {
		return nil, fmt.Errorf("VAES128: Invalid cipher size")
	}

	// Reconstruct complete IV and message key
	iv := make([]byte, aes.BlockSize)
	copy(iv, ciph[:rivLen])
	copy(iv[rivLen:], k.static_iv)

	msgk := make([]byte, aes.BlockSize)
	copy(msgk, ciph[rivLen:rivLen+rmsgkLen])
	copy(msgk[rmsgkLen:], k.static_msgk)

	// Decrypt the message
	ciph = ciph[rivLen+rmsgkLen:]
	plain := make([]byte, len(ciph))
	block, err := aes.NewCipher(msgk)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plain, ciph)
	padnum := int(plain[len(plain)-1])
	if padnum > len(plain) {
		return nil, fmt.Errorf("VAES128: Invalid cipher buf")
	}
	return plain[:len(plain)-padnum], nil
}

// Decrypt hstr using VAES128
func (k Key) DecryptHstr(hstr string) ([]byte, error) {
	ciph, err := hex.DecodeString(hstr)
	if err != nil {
		return nil, err
	}
	return k.Decrypt(ciph)
}
