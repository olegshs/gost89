package gost89

func (this *Gost89) EncryptBytesECB(plain []byte) []byte {
	length := len(plain)
	var encrypted []byte

	for i := 0; i < length; i += 8 {
		block := plain[i : i+8]
		block = this.EncryptBytes(block)

		encrypted = append(encrypted, block...)
	}

	return encrypted[:length]
}

func (this *Gost89) DecryptBytesECB(encrypted []byte) []byte {
	length := len(encrypted)
	var plain []byte

	for i := 0; i < length; i += 8 {
		block := encrypted[i : i+8]
		block = this.DecryptBytes(block)

		plain = append(plain, block...)
	}

	return plain[:length]
}
