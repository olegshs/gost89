package gost89

import (
	"bytes"
	"encoding/binary"
)

type Block64 [2]uint32
type Block256 [8]uint32
type SboxArray [8][16]uint8

type Gost89 struct {
	sbox   SboxArray
	sbox_x [4][256]uint32
	key    Block256
	iv     Block64
	mac    Block64
}

func (this *Gost89) SetSbox(sbox SboxArray) {
	for i := 0; i < 8; i++ {
		for j := 0; j < 16; j++ {
			this.sbox[i][j] = sbox[i][j]
		}
	}

	this.expandSbox()
}

func (this *Gost89) expandSbox() {
	for i := 0; i < 256; i++ {
		j := i / 16
		k := i % 16

		this.sbox_x[0][i] = uint32(this.sbox[1][j]<<4 | this.sbox[0][k])
		this.sbox_x[1][i] = uint32(this.sbox[3][j]<<4 | this.sbox[2][k])
		this.sbox_x[2][i] = uint32(this.sbox[5][j]<<4 | this.sbox[4][k])
		this.sbox_x[3][i] = uint32(this.sbox[7][j]<<4 | this.sbox[6][k])
	}
}

func (this *Gost89) SetKey(key Block256) {
	for i := 0; i < 8; i++ {
		this.key[i] = key[i]
	}
}

func (this *Gost89) SetKeyBytes(key []byte) {
	buf := bytes.NewReader(key)
	binary.Read(buf, binary.LittleEndian, &this.key)
}

func (this *Gost89) SetIv(iv Block64) {
	this.iv = iv
}

func (this *Gost89) SetIvBytes(iv []byte) {
	this.iv = BytesToBlock64(iv)
}

func (this *Gost89) Round(block uint32, key uint32) uint32 {
	t := block + key

	t = uint32(this.sbox_x[0][t&0xFF]) |
		uint32(this.sbox_x[1][t>>8&0xFF])<<8 |
		uint32(this.sbox_x[2][t>>16&0xFF])<<16 |
		uint32(this.sbox_x[3][t>>24&0xFF])<<24

	t = t<<11 | t>>21

	return t
}

func (this *Gost89) Encrypt(plain Block64) Block64 {
	a := plain[0]
	b := plain[1]

	for i := 0; i < 3; i++ {
		/*
			b ^= this.Round(a, this.key[0])
			a ^= this.Round(b, this.key[1])
			b ^= this.Round(a, this.key[2])
			a ^= this.Round(b, this.key[3])
			b ^= this.Round(a, this.key[4])
			a ^= this.Round(b, this.key[5])
			b ^= this.Round(a, this.key[6])
			a ^= this.Round(b, this.key[7])
		*/
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

	/*
		b ^= this.Round(a, this.key[7])
		a ^= this.Round(b, this.key[6])
		b ^= this.Round(a, this.key[5])
		a ^= this.Round(b, this.key[4])
		b ^= this.Round(a, this.key[3])
		a ^= this.Round(b, this.key[2])
		b ^= this.Round(a, this.key[1])
		a ^= this.Round(b, this.key[0])
	*/
	for j := 7; j > 0; j -= 2 {
		t := a + this.key[j]
		t = uint32(this.sbox_x[0][t&0xFF]) |
			uint32(this.sbox_x[1][t>>8&0xFF])<<8 |
			uint32(this.sbox_x[2][t>>16&0xFF])<<16 |
			uint32(this.sbox_x[3][t>>24&0xFF])<<24
		b ^= t<<11 | t>>21

		t = b + this.key[j-1]
		t = uint32(this.sbox_x[0][t&0xFF]) |
			uint32(this.sbox_x[1][t>>8&0xFF])<<8 |
			uint32(this.sbox_x[2][t>>16&0xFF])<<16 |
			uint32(this.sbox_x[3][t>>24&0xFF])<<24
		a ^= t<<11 | t>>21
	}

	return Block64{b, a}
}

func (this *Gost89) EncryptBytes(plain []byte) []byte {
	t := BytesToBlock64(plain)
	t = this.Encrypt(t)
	return Block64ToBytes(t)
}

func (this *Gost89) Decrypt(encrypted Block64) Block64 {
	a := encrypted[0]
	b := encrypted[1]

	/*
		b ^= this.Round(a, this.key[0])
		a ^= this.Round(b, this.key[1])
		b ^= this.Round(a, this.key[2])
		a ^= this.Round(b, this.key[3])
		b ^= this.Round(a, this.key[4])
		a ^= this.Round(b, this.key[5])
		b ^= this.Round(a, this.key[6])
		a ^= this.Round(b, this.key[7])
	*/
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

	for i := 0; i < 3; i++ {
		/*
			b ^= this.Round(a, this.key[7])
			a ^= this.Round(b, this.key[6])
			b ^= this.Round(a, this.key[5])
			a ^= this.Round(b, this.key[4])
			b ^= this.Round(a, this.key[3])
			a ^= this.Round(b, this.key[2])
			b ^= this.Round(a, this.key[1])
			a ^= this.Round(b, this.key[0])
		*/
		for j := 7; j > 0; j -= 2 {
			t := a + this.key[j]
			t = uint32(this.sbox_x[0][t&0xFF]) |
				uint32(this.sbox_x[1][t>>8&0xFF])<<8 |
				uint32(this.sbox_x[2][t>>16&0xFF])<<16 |
				uint32(this.sbox_x[3][t>>24&0xFF])<<24
			b ^= t<<11 | t>>21

			t = b + this.key[j-1]
			t = uint32(this.sbox_x[0][t&0xFF]) |
				uint32(this.sbox_x[1][t>>8&0xFF])<<8 |
				uint32(this.sbox_x[2][t>>16&0xFF])<<16 |
				uint32(this.sbox_x[3][t>>24&0xFF])<<24
			a ^= t<<11 | t>>21
		}
	}

	return Block64{b, a}
}

func (this *Gost89) DecryptBytes(encrypted []byte) []byte {
	t := BytesToBlock64(encrypted)
	t = this.Decrypt(t)
	return Block64ToBytes(t)
}

func BytesToBlock64(b []byte) Block64 {
	return Block64{
		uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24,
		uint32(b[4]) | uint32(b[5])<<8 | uint32(b[6])<<16 | uint32(b[7])<<24,
	}
}

func Block64ToBytes(i Block64) []byte {
	return []byte{
		byte(i[0]),
		byte(i[0] >> 8),
		byte(i[0] >> 16),
		byte(i[0] >> 24),
		byte(i[1]),
		byte(i[1] >> 8),
		byte(i[1] >> 16),
		byte(i[1] >> 24),
	}
}
