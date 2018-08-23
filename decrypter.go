// Copyright 2018 Ajitem Sahasrabuddhe
// The use of the code is governed by the MIT License.
// Please refer to the accompanying LICENSE file for more details.

package aes_ecb_mode

import "crypto/cipher"

type ecbDecrypter ecb

func (d *ecbDecrypter) BlockSize() int {
	return d.block.BlockSize()
}

func (d *ecbDecrypter) CryptBlocks(encryptedText, plainText []byte) {
	blockSize := d.BlockSize()

	if len(encryptedText) % blockSize != 0 {
		panic("crypto/cipher: input not full blocks.")
	}
	if len(plainText) < len(encryptedText) {
		panic("ecbEncrypter.CryptBlocks: output is smaller than the input. Please ensure that the output is" +
			" large enough to store the input.")
	}
	for len(encryptedText) > 0 {
		d.block.Decrypt(plainText, encryptedText[:blockSize])
		encryptedText = encryptedText[blockSize:]
		plainText = plainText[blockSize:]
	}

}

// Returns a new AES Decrypter in ECB Mode

func NewDecrypter(block cipher.Block) cipher.BlockMode {
	return &ecbDecrypter{block: block}
}