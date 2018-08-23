// Copyright 2018 Ajitem Sahasrabuddhe
// The use of the code is governed by the MIT License.
// Please refer to the accompanying LICENSE file for more details.

package aes_ecb_mode

import (
	"testing"
	"crypto/aes"
	"log"
)

var plainText, encryptedText []byte

func init() {
	b, err := aes.NewCipher([]byte(KEY))
	if err != nil {
		log.Fatal(err)
	}

	plainText = []byte("Hello, World!")
	paddedPlainText := Pad(plainText)
	encryptedText = make([]byte, len(paddedPlainText))

	e := NewEncrypter(b)

	e.CryptBlocks(encryptedText, paddedPlainText)
}

func TestNewDecrypter(t *testing.T) {
	b, err := aes.NewCipher([]byte(KEY))
	if err != nil {
		t.Error(err)
	}

	NewDecrypter(b)
}

func TestEcbDecrypter_BlockSize(t *testing.T) {
	b, err := aes.NewCipher([]byte(KEY))
	if err != nil {
		t.Error(err)
	}

	d := NewDecrypter(b)

	blockSize := d.BlockSize()

	if blockSize != aes.BlockSize {
		t.Errorf("Incorrect blocksize. want %v. got %v.", aes.BlockSize, blockSize)
	}
}

func TestEcbDecrypter_CryptBlocks_Panic_Without_Base64_Decode(t *testing.T) {
	defer func() {
		r := recover()
		t.Log(r)
	}()

	b, err := aes.NewCipher([]byte(KEY))
	if err != nil {
		t.Error(err)
	}

	d := NewDecrypter(b)

	paddedPlainText := make([]byte, len(encryptedText))

	d.CryptBlocks(encryptedText, paddedPlainText[15:])
	unpaddedPlainText, err := UnPad(paddedPlainText)

	if err != nil {
		t.Error(err)
	}

	if string(unpaddedPlainText) != string(paddedPlainText) {
		t.Errorf("Decryption failed. want %v. got %v", plainText, unpaddedPlainText)
	}
}

func TestEcbDecrypter_CryptBlocks_Panic_On_Unequal_Src_And_Dest(t *testing.T) {
	defer func() {
		r := recover()
		t.Log(r)
	}()

	b, err := aes.NewCipher([]byte(KEY))
	if err != nil {
		t.Error(err)
	}

	d := NewDecrypter(b)

	paddedPlainText := make([]byte, len(encryptedText) - 1)

	d.CryptBlocks(paddedPlainText, encryptedText)
	unpaddedPlainText, err := UnPad(paddedPlainText)

	if err != nil {
		t.Error(err)
	}

	if string(unpaddedPlainText) != string(paddedPlainText) {
		t.Errorf("Decryption failed. want %v. got %v", plainText, unpaddedPlainText)
	}
}

func TestEcbDecrypter_CryptBlocks(t *testing.T) {
	b, err := aes.NewCipher([]byte(KEY))
	if err != nil {
		t.Error(err)
	}

	d := NewDecrypter(b)

	paddedPlainText := make([]byte, len(encryptedText))

	d.CryptBlocks(paddedPlainText, encryptedText)
	unpaddedPlainText, err := UnPad(paddedPlainText)

	if err != nil {
		t.Error(err)
	}

	if string(unpaddedPlainText) != string(paddedPlainText) {
		t.Errorf("Decryption failed. want %v. got %v", plainText, unpaddedPlainText)
	}
}

func BenchmarkNewDecrypter(b *testing.B) {

}

func BenchmarkEcbDecrypter_BlockSize(b *testing.B) {

}

func BenchmarkEcbDecrypter_CryptBlocks(b *testing.B) {

}