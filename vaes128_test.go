package vaes128

import (
	"testing"
)

// AES test: IV length = 0, message key length = 16
func TestAES128AES(t *testing.T) {
	key := New("", "1234567890123456")
	plaintext := []byte("Hello!")
	ciphertext, err := key.Encrypt(plaintext)
	if err != nil {
		t.Error(err)
	}
	decrypted, err := key.Decrypt(ciphertext)
	if err != nil {
		t.Error(err)
	}
	if string(decrypted) != string(plaintext) {
		t.Error("Decrypted plaintext does not match original plaintext")
	}
}

// VAES test: IV length = 12, message key length = 12
func TestVAES128(t *testing.T) {
	key := New("0123456789abc", "123456789012")
	plaintext := []byte("Hello!")
	ciphertext, err := key.Encrypt(plaintext)
	if err != nil {
		t.Error(err)
	}
	decrypted, err := key.Decrypt(ciphertext)
	if err != nil {
		t.Error(err)
	}
	if string(decrypted) != string(plaintext) {
		t.Error("Decrypted plaintext does not match original plaintext")
	}
}

// VAES test: IV length = 4, message key length = 12
func TestVAES128LenDiff(t *testing.T) {
	key := New("0123", "123456789012")
	plaintext := []byte("Hello!")
	ciphertext, err := key.Encrypt(plaintext)
	if err != nil {
		t.Error(err)
	}
	decrypted, err := key.Decrypt(ciphertext)
	if err != nil {
		t.Error(err)
	}
	if string(decrypted) != string(plaintext) {
		t.Error("Decrypted plaintext does not match original plaintext")
	}
}

// VAES test: IV length = 12, message key length = 12, plain length = 0
func TestVAES128Len0(t *testing.T) {
	key := New("0123456789abc", "123456789012")
	plaintext := []byte("")
	ciphertext, err := key.Encrypt(plaintext)
	if err != nil {
		t.Error(err)
	}
	decrypted, err := key.Decrypt(ciphertext)
	if err != nil {
		t.Error(err)
	}
	if string(decrypted) != string(plaintext) {
		t.Error("Decrypted plaintext does not match original plaintext")
	}
}

// VAES test: IV length = 12, message key length = 12, plain length = multiple of 16 (32)
func TestVAES128Len16(t *testing.T) {
	key := New("0123456789abc", "123456789012")
	plaintext := []byte("12345678901234567890123456789012")
	ciphertext, err := key.Encrypt(plaintext)
	if err != nil {
		t.Error(err)
	}
	decrypted, err := key.Decrypt(ciphertext)
	if err != nil {
		t.Error(err)
	}
	if string(decrypted) != string(plaintext) {
		t.Error("Decrypted plaintext does not match original plaintext")
	}
}

// VAES test: hstr
func TestVAES128Hstr(t *testing.T) {
	key := New("0123456789abc", "123456789012")
	plaintext := []byte("hello!")
	ciphertext, err := key.EncryptHstr(plaintext)
	if err != nil {
		t.Error(err)
	}
	decrypted, err := key.DecryptHstr(ciphertext)
	if err != nil {
		t.Error(err)
	}
	if string(decrypted) != string(plaintext) {
		t.Error("Decrypted plaintext does not match original plaintext")
	}
}

func BenchmarkVAES128(b *testing.B) {
	key := New("0123456789abc", "123456789012")
	plaintext := []byte("hello!")
	for i := 0; i < b.N; i++ {
		ciphertext, _ := key.Encrypt(plaintext)
		_, _ = key.Decrypt(ciphertext)
	}
}
