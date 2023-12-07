package gost89

import (
	"fmt"
)

func (this *Gost89) PrintSbox() {
	for i := 0; i < 8; i++ {
		for j := 0; j < 16; j++ {
			fmt.Printf("%d, ", this.sbox[i][j])
		}
		fmt.Println()
	}
}

func (this *Gost89) PrintKey() {
	for i := 0; i < 8; i++ {
		fmt.Printf("%08x ", this.key[i])
	}
	fmt.Println()
}

func (this *Gost89) PrintIv() {
	fmt.Printf("%08x%08x\n", this.iv[1], this.iv[0])
}
