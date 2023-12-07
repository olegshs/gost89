package gost89

func (this *Gost89) GetMac() uint32 {
	return this.mac[1]
}

func (this *Gost89) ResetMac() {
	this.mac[0] = 0
	this.mac[1] = 0
}

func (this *Gost89) ComputeMac(plain []byte) uint32 {
	length := len(plain)

	for i := 0; i < length; i += 8 {
		block := BytesToBlock64(plain[i : i+8])
		this.mac[0] ^= block[0]
		this.mac[1] ^= block[1]

		this.mac = this.encrypt16(this.mac)
	}

	return this.mac[1]
}

func (this *Gost89) encrypt16(plain Block64) Block64 {
	a := plain[0]
	b := plain[1]

	for i := 0; i < 2; i++ {
		for j := 0; j < 8; j += 2 {
			t := a + this.key[j]
			t = uint32(this.sbox_x[0][t&0xFF]) |
				uint32(this.sbox_x[1][t>>8&0xFF])<<8 |
				uint32(this.sbox_x[2][t>>16&0xFF])<<16 |
				uint32(this.sbox_x[3][t>>24&0xFF])<<24
			b ^= t<<11 | t>>21

			t = b + this.key[j+1]
			t = uint32(this.sbox_x[0][t&0xFF]) |
				uint32(this.sbox_x[1][t>>8&0xFF])<<8 |
				uint32(this.sbox_x[2][t>>16&0xFF])<<16 |
				uint32(this.sbox_x[3][t>>24&0xFF])<<24
			a ^= t<<11 | t>>21
		}
	}

	return Block64{a, b}
}
