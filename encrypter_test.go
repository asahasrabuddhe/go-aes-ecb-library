// Copyright 2018 Ajitem Sahasrabuddhe
// The use of the code is governed by the MIT License.
// Please refer to the accompanying LICENSE file for more details.

package aes_ecb_mode

import (
	"testing"
	"crypto/aes"
)

const KEY = "883eadc0cbf90c42e0f19dba78195e10"

func TestNewEncrypter(t *testing.T) {
	b, err := aes.NewCipher([]byte(KEY))
	if err != nil {
		t.Error(err)
	}

	NewEncrypter(b)
}

func TestEcbEncrypter_BlockSize(t *testing.T) {
	b, err := aes.NewCipher([]byte(KEY))
	if err != nil {
		t.Error(err)
	}

	e := NewEncrypter(b)

	blockSize := e.BlockSize()

	if blockSize != aes.BlockSize {
		t.Errorf("Incorrect blocksize. want %v. got %v.", aes.BlockSize, blockSize)
	}
}

func TestEcbEncrypter_CryptBlocks_Error_Without_Padding(t *testing.T) {
	defer func() {
		r := recover()
		t.Log(r)
	}()

	b, err := aes.NewCipher([]byte(KEY))
	if err != nil {
		t.Error(err)
	}

	plainText := []byte("Hello, World!")
	encryptedText := make([]byte, len(plainText))

	e := NewEncrypter(b)

	e.CryptBlocks(encryptedText, plainText)
	t.Error("Did not panic!")
}

func TestEcbEncrypter_CryptBlocks_Error_On_Unequal_Src_And_Dest(t *testing.T) {
	defer func() {
		r := recover()
		t.Log(r)
	}()

	b, err := aes.NewCipher([]byte(KEY))
	if err != nil {
		t.Error(err)
	}

	plainText := []byte("Hello, World!")
	paddedPlainText := Pad(plainText)
	encryptedText := make([]byte, len(paddedPlainText) - 1)

	e := NewEncrypter(b)

	e.CryptBlocks(encryptedText, paddedPlainText)
	t.Error("Did not panic!")
}

func TestEcbEncrypter_CryptBlocks(t *testing.T) {
	b, err := aes.NewCipher([]byte(KEY))
	if err != nil {
		t.Error(err)
	}

	plainText := []byte("Hello, World!")
	paddedPlainText := Pad(plainText)
	encryptedText := make([]byte, len(paddedPlainText))

	e := NewEncrypter(b)

	e.CryptBlocks(encryptedText, paddedPlainText)
}

func BenchmarkNewEncrypter(b *testing.B) {

}

func BenchmarkEcbEncrypter_BlockSize(b *testing.B) {

}

func BenchmarkEcbEncrypter_CryptBlocks(b *testing.B) {

}
