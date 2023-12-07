package gost89

import (
	"crypto/cipher"
	"errors"
)

type gost89Cipher struct {
	gost89 Gost89
}

func NewCipher(key []byte) (cipher.Block, error) {
	l := len(key)
	if l != 32 {
		return nil, errors.New("Invalid key size: " + string(l))
	}

	c := new(gost89Cipher)
	c.gost89.SetSbox(SboxTest)
	c.gost89.SetKeyBytes(key)

	return c, nil
}

func (this *gost89Cipher) BlockSize() int {
	return 8
}

func (this *gost89Cipher) Encrypt(dst, src []byte) {
	t := BytesToBlock64(src)
	t = this.gost89.Encrypt(t)
	dst = Block64ToBytes(t)
}

func (this *gost89Cipher) Decrypt(dst, src []byte) {
	t := BytesToBlock64(src)
	t = this.gost89.Decrypt(t)
	dst = Block64ToBytes(t)
}
