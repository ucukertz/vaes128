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
	// Generate full IV and message key
	riv := make([]byte, aes.BlockSize-len(k.static_iv), aes.BlockSize)
	rand.Read(riv)
	iv := append(riv, k.static_iv...)
	rmsgk := make([]byte, aes.BlockSize-len(k.static_msgk), aes.BlockSize)
	rand.Read(rmsgk)
	msgk := append(rmsgk, k.static_msgk...)

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
	var pnum byte = byte(padnum)
	padding := make([]byte, pnum)
	for i := 0; i < padnum; i++ {
		padding[i] = pnum
	}
	padded := append(plain, padding...)

	// Encrypt and prepend random part of IV and message key
	cipherbuf := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherbuf, padded)
	ciph := append(riv, rmsgk...)
	ciph = append(ciph, cipherbuf...)
	return ciph, nil
}

// Encrypt buf using VAES128 and convert the result to hex string
func (k Key) EncryptHstr(plain []byte) (string, error) {
	ciph, err := k.Encrypt(plain)
	if err != nil {
		return "", err
	}
	hstr := hex.EncodeToString(ciph)
	return hstr, err
}

// Decrypt cipherbuf using VAES128
func (k Key) Decrypt(ciph []byte) ([]byte, error) {
	riv_len := aes.BlockSize - len(k.static_iv)
	rmsgk_len := aes.BlockSize - len(k.static_msgk)
	padded_len := len(ciph) - riv_len - rmsgk_len

	if padded_len%aes.BlockSize != 0 {
		return nil, fmt.Errorf("VAES128: Invalid cipher size")
	}

	// Reconstruct complete IV and message key
	riv := make([]byte, riv_len, aes.BlockSize)
	copy(riv, ciph[:riv_len])
	iv := append(riv, k.static_iv...)
	rmsgk := make([]byte, rmsgk_len, aes.BlockSize)
	copy(rmsgk, ciph[riv_len:riv_len+rmsgk_len])
	msgk := append(rmsgk, k.static_msgk...)

	// Decrypt the message
	ciph = ciph[riv_len+rmsgk_len:]
	plain := make([]byte, len(ciph))
	block, err := aes.NewCipher(msgk)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plain, ciph)
	padnum := int(plain[len(plain)-1])
	if len(plain)-padnum >= 0 {
		plain = plain[:len(plain)-padnum]
	} else {
		return []byte{}, fmt.Errorf("VAES128: Invalid cipher buf")
	}
	return plain, nil
}

// Decrypt hstr using VAES128
func (k Key) DecryptHstr(hstr string) ([]byte, error) {
	ciph, err := hex.DecodeString(hstr)
	if err != nil {
		return nil, err
	}
	buf, err := k.Decrypt(ciph)
	if err != nil {
		return nil, err
	}
	return buf, nil
}
