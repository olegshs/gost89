package gost89

func (this *Gost89) InitCTR() {
	this.iv = this.Encrypt(this.iv)
}

func (this *Gost89) EncryptBytesCTR(plain []byte) []byte {
	length := len(plain)
	var encrypted []byte

	for i := 0; i < length; i += 8 {
		this.iv[0] += 0x1010101
		if this.iv[1] > 0xFFFFFFFF-0x1010104 {
			this.iv[1] += 0x1010104 + 1
		} else {
			this.iv[1] += 0x1010104
		}

		t := this.Encrypt(this.iv)
		block := BytesToBlock64(plain[i : i+8])
		block[0] ^= t[0]
		block[1] ^= t[1]

		encrypted = append(encrypted, Block64ToBytes(block)...)
	}

	return encrypted[:length]
}
