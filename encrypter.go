// Copyright 2018 Ajitem Sahasrabuddhe
// The use of the code is governed by the MIT License.
// Please refer to the accompanying LICENSE file for more details.

package aes_ecb_mode

import "crypto/cipher"

type ecbEncrypter ecb

func (e *ecbEncrypter) BlockSize() int {
	return e.block.BlockSize()
}

func (e *ecbEncrypter) CryptBlocks(encryptedText, plainText []byte) {
	blockSize := e.BlockSize()

	if len(plainText) % blockSize != 0 {
		panic("ecbEncrypter.CryptBlocks: input not full blocks. Please pad the input and try again.")
	}

	if len(encryptedText) < len(plainText) {
		panic("ecbEncrypter.CryptBlocks: output is smaller than the input. Please ensure that the output is" +
			" large enough to store the input.")
	}
	for len(plainText) > 0 {
		e.block.Encrypt(encryptedText, plainText[:e.BlockSize()])
		plainText = plainText[e.BlockSize():]
		encryptedText = encryptedText[e.BlockSize():]
	}
}

// Returns a new AES Encrypter in ECB Mode

func NewEncrypter(block cipher.Block) cipher.BlockMode {
	return &ecbEncrypter{block: block}
}