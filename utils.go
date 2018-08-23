// Copyright 2018 Ajitem Sahasrabuddhe
// The use of the code is governed by the MIT License.
// Please refer to the accompanying LICENSE file for more details.

package aes_ecb_mode

import (
	"crypto/aes"
	"bytes"
	"errors"
)

// Pads the plain text so that the length of the plain text is a multiple of AES Block Size (16).
// Padding is done *before* the encryption process.

func Pad(plainText []byte) []byte {
	padding := aes.BlockSize - len(plainText) % aes.BlockSize

	paddedText := bytes.Repeat([]byte{byte(padding)}, padding)

	return append(plainText, paddedText...)
}

// Unpadding will remove the extra padding bytes added before encryption.
// Unpadding is done *after* the decryption process.

func UnPad(encryptedText []byte) ([]byte, error) {
	length := len(encryptedText)
	padding := int(encryptedText[length-1])

	if padding > length {
		return nil, errors.New("unpad error. This could happen when incorrect encryption key is used")
	}

	return encryptedText[:(length - padding)], nil
}