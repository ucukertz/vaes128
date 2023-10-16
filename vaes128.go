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

// Set static part of keys to be used for encryption and decryption using VAES128 len=0-16 for both.
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
func (k Key) Encrypt(buf []byte) ([]byte, error) {
	// Generate full IV and message key
	riv := make([]byte, aes.BlockSize-len(k.static_iv))
	rand.Read(riv)
	iv := append(riv, k.static_iv...)
	rmsgk := make([]byte, aes.BlockSize-len(k.static_msgk))
	rand.Read(rmsgk)
	msgk := append(rmsgk, k.static_msgk...)

	// Create cipher and calculate required sizes for ciphertext
	block, err := aes.NewCipher(msgk)
	if err != nil {
		return nil, err
	}
	blocknum := len(buf)/aes.BlockSize + 1
	padnum := blocknum*aes.BlockSize - len(buf)

	// Pad the message
	if padnum == 0 {
		padnum = aes.BlockSize
	}
	padding := make([]byte, padnum)
	for i := 0; i < padnum; i++ {
		padding[i] = byte(padnum)
	}
	padded := append(buf, padding...)

	// Encrypt and prepend random part of IV and message key
	cipherbuf := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherbuf, padded)
	cipherbuf = append(rmsgk, cipherbuf...)
	cipherbuf = append(riv, cipherbuf...)
	return cipherbuf, nil
}

// Encrypt buf using VAES128 and convert the result to hex string
func (k Key) EncryptHstr(buf []byte) (string, error) {
	cipherbuf, err := k.Encrypt(buf)
	if err != nil {
		return "", err
	}
	hstr := hex.EncodeToString(cipherbuf)
	return hstr, err
}

// Decrypt cipherbuf using VAES128
func (k Key) Decrypt(cipherbuf []byte) ([]byte, error) {
	riv_len := aes.BlockSize - len(k.static_iv)
	rmsgk_len := aes.BlockSize - len(k.static_msgk)
	padded_len := len(cipherbuf) - riv_len - rmsgk_len

	if padded_len%aes.BlockSize != 0 {
		return nil, fmt.Errorf("VAES128: Invalid cipher size")
	}

	// Reconstruct complete IV and message key
	riv := make([]byte, riv_len)
	copy(riv, cipherbuf[:riv_len])
	iv := append(riv, k.static_iv...)
	rmsgk := make([]byte, rmsgk_len)
	copy(rmsgk, cipherbuf[riv_len:riv_len+rmsgk_len])
	msgk := append(rmsgk, k.static_msgk...)

	// Decrypt the message
	cipherbuf = cipherbuf[riv_len+rmsgk_len:]
	buf := make([]byte, len(cipherbuf))
	block, err := aes.NewCipher(msgk)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(buf, cipherbuf)
	padnum := int(buf[len(buf)-1])
	if len(buf)-padnum >= 0 {
		buf = buf[:len(buf)-padnum]
	} else {
		return []byte{}, fmt.Errorf("VAES128: Invalid cipher buf")
	}
	return buf, nil
}

// Decrypt hstr using VAES128
func (k Key) DecryptHstr(hstr string) ([]byte, error) {
	cipherbuf, err := hex.DecodeString(hstr)
	if err != nil {
		return nil, err
	}
	buf, err := k.Decrypt(cipherbuf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}
