// Copyright 2018 Ajitem Sahasrabuddhe
// The use of the code is governed by the MIT License.
// Please refer to the accompanying LICENSE file for more details.

package aes_ecb_mode

import (
	"testing"
	"bytes"
	"crypto/aes"
)

func TestPad(t *testing.T) {
	plainText := bytes.NewBufferString("Hello, World")
	paddedText := Pad(plainText.Bytes())

	if len(paddedText) % aes.BlockSize != 0 {
		t.Errorf("Length of plain text was not a multiple of 16. Got %v", len(paddedText))
	}

	padding := len(paddedText) - len(plainText.String())
	for i := len(plainText.String()); i < len(paddedText); i++ {
		if byte(paddedText[i]) != byte(padding) {
			t.Errorf("Padding incorrect. got %v. want %v.", paddedText[i], padding)
		}
	}
}

func TestUnPad(t *testing.T) {
	plainText := bytes.NewBufferString("Hello, World")
	paddedText := Pad(plainText.Bytes())

	_, err := UnPad(append(paddedText, []byte("56")...))

	if err == nil {
		t.Error("No exception thrown")
	}

}

func BenchmarkPad(b *testing.B) {

}

func BenchmarkUnPad(b *testing.B) {

}
