package main

import (
	"./gost89"
	"fmt"
	"io/ioutil"
	"time"
)

func main() {
	cipher := new(gost89.Gost89)

	cipher.SetSbox(gost89.SboxTest)
	cipher.PrintSbox()

	cipher.SetKeyBytes([]byte("01234567890123456789012345678912"))
	cipher.PrintKey()

	plain := []byte("ABCDEFGH")
	for i := 0; i < 8; i++ {
		fmt.Printf("%02x ", plain[i])
	}
	fmt.Println()

	encrypted := cipher.EncryptBytes(plain)
	for i := 0; i < 8; i++ {
		fmt.Printf("%02x ", encrypted[i])
	}
	fmt.Println()

	plain = cipher.DecryptBytes(encrypted)
	for i := 0; i < 8; i++ {
		fmt.Printf("%02x ", plain[i])
	}
	fmt.Println()

	testECB(cipher)
	testCTR(cipher)
	testCFB(cipher)
	benchmark(cipher)
}

func getSampleText() string {
	return "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et " +
		"dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex " +
		"ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu " +
		"fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt " +
		"mollit anim id est laborum. OLOLO!!!11"
}

func testECB(cipher *gost89.Gost89) {
	plain := []byte(getSampleText())
	encrypted := cipher.EncryptBytesECB(plain)
	decrypted := cipher.DecryptBytesECB(encrypted)

	mac := cipher.ComputeMac(plain)
	fmt.Printf("%08x\n", mac)

	ioutil.WriteFile("ecb.0", plain, 0644)
	ioutil.WriteFile("ecb.1", encrypted, 0644)
	ioutil.WriteFile("ecb.2", decrypted, 0644)
}

func testCTR(cipher *gost89.Gost89) {
	plain := []byte(getSampleText())

	cipher.SetIv(gost89.Block64{0xFF, 0})
	cipher.PrintIv()
	cipher.InitCTR()
	encrypted := cipher.EncryptBytesCTR(plain)

	cipher.SetIv(gost89.Block64{0xFF, 0})
	cipher.InitCTR()
	decrypted := cipher.EncryptBytesCTR(encrypted)

	ioutil.WriteFile("ctr.0", plain, 0644)
	ioutil.WriteFile("ctr.1", encrypted, 0644)
	ioutil.WriteFile("ctr.2", decrypted, 0644)
}

func testCFB(cipher *gost89.Gost89) {
	plain := []byte(getSampleText())

	cipher.SetIv(gost89.Block64{0xFF, 0})
	cipher.PrintIv()
	encrypted := cipher.EncryptBytesCFB(plain)

	cipher.SetIv(gost89.Block64{0xFF, 0})
	decrypted := cipher.DecryptBytesCFB(encrypted)

	ioutil.WriteFile("cfb.0", plain, 0644)
	ioutil.WriteFile("cfb.1", encrypted, 0644)
	ioutil.WriteFile("cfb.2", decrypted, 0644)
}

func benchmark(cipher *gost89.Gost89) {
	var (
		a [2]uint32
		b [2]uint32
	)
	a = gost89.BytesToBlock64([]byte("ABCDEFGH"))

	t0 := time.Now()

	for i := 0; i < 5000000; i++ {
		b = cipher.Encrypt(a)
		a = cipher.Encrypt(b)
	}
	for i := 0; i < 5000000; i++ {
		b = cipher.Decrypt(a)
		a = cipher.Decrypt(b)
	}

	t1 := time.Now()

	c := gost89.Block64ToBytes(a)
	for i := 0; i < 8; i++ {
		fmt.Printf("%02x ", c[i])
	}
	fmt.Println()

	fmt.Print(uint64(t1.Sub(t0) / time.Millisecond))
	fmt.Println(" ms")
}
