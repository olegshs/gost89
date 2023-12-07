package gost89

func (this *Gost89) EncryptBytesCFB(plain []byte) []byte {
	length := len(plain)
	var encrypted []byte

	for i := 0; i < length; i += 8 {
		t := this.Encrypt(this.iv)
		block := BytesToBlock64(plain[i : i+8])
		block[0] ^= t[0]
		block[1] ^= t[1]
		this.iv = block

		encrypted = append(encrypted, Block64ToBytes(block)...)
	}

	return encrypted[:length]
}

func (this *Gost89) DecryptBytesCFB(encrypted []byte) []byte {
	length := len(encrypted)
	var plain []byte

	for i := 0; i < length; i += 8 {
		t := this.Encrypt(this.iv)
		block := BytesToBlock64(encrypted[i : i+8])
		this.iv = block
		block[0] ^= t[0]
		block[1] ^= t[1]

		plain = append(plain, Block64ToBytes(block)...)
	}

	return plain[:length]
}
