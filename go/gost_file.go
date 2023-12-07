package main

import (
	"./gost89"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const ioBufSize = 0x10000

const (
	operation_none = iota
	operation_encrypt
	operation_decrypt
	operation_mac
)

const (
	mode_none = iota
	mode_ecb
	mode_ctr
	mode_cfb
)

var options struct {
	operation  int
	mode       int
	computeMac bool
	sboxFile   string
	keyFile    string
	iv         string
	inFile     string
	outFile    string
	debug      bool
}

func main() {
	runtime.GOMAXPROCS(2)

	parseCommandLine()

	checkFileExists(options.sboxFile)
	checkFileExists(options.keyFile)
	checkFileExists(options.inFile)

	cipher := new(gost89.Gost89)

	readSbox(cipher, options.sboxFile)
	readKey(cipher, options.keyFile)

	if (options.operation == operation_encrypt || options.operation == operation_decrypt) &&
		(options.mode == mode_ctr || options.mode == mode_cfb) {
		parseIv(cipher, options.iv)
	}

	if options.debug {
		cipher.PrintSbox()
		cipher.PrintKey()
		cipher.PrintIv()
	}

	switch options.operation {
	case operation_encrypt:
		fmt.Print("Encrypting")
	case operation_decrypt:
		fmt.Print("Decrypting")
	case operation_mac:
		fmt.Print("Computing MAC")
	}

	if options.operation != operation_mac {
		switch options.mode {
		case mode_ecb:
			fmt.Print(" in ECB mode")
		case mode_ctr:
			fmt.Print(" in CTR mode")
		case mode_cfb:
			fmt.Print(" in CFB mode")
		}
	}

	fmt.Print(": " + options.inFile)

	if len(options.outFile) > 0 {
		fmt.Print(" -> " + options.outFile)
	}

	fmt.Println()

	prevProgress := -1

	printProgress := func(complete int64, total int64) {
		progress := int(100 * complete / total)
		if progress > prevProgress {
			prevProgress = progress
			fmt.Printf("\r%d%%", progress)
		}
	}

	t0 := time.Now()

	switch options.operation {
	case operation_encrypt:
		encrypt(cipher, options.mode, options.computeMac, options.inFile, options.outFile, printProgress)
	case operation_decrypt:
		decrypt(cipher, options.mode, options.computeMac, options.inFile, options.outFile, printProgress)
	case operation_mac:
		computeMac(cipher, options.inFile, printProgress)
	}

	t1 := time.Now()

	fmt.Printf("\r%d ms\n", t1.Sub(t0)/time.Millisecond)

	if options.computeMac {
		mac := cipher.GetMac()
		fmt.Printf("\nMAC: %08x\n", mac)
	}
}

func parseCommandLine() {
	var (
		encrypt bool
		decrypt bool
		mac     bool
		mode    string
	)

	flag.BoolVar(&encrypt, "e", false, "")
	flag.BoolVar(&encrypt, "encrypt", false, "")

	flag.BoolVar(&decrypt, "d", false, "")
	flag.BoolVar(&decrypt, "decrypt", false, "")

	flag.BoolVar(&mac, "a", false, "")
	flag.BoolVar(&mac, "mac", false, "")

	flag.StringVar(&mode, "m", "", "")
	flag.StringVar(&mode, "mode", "", "")

	flag.StringVar(&options.sboxFile, "s", "", "")
	flag.StringVar(&options.sboxFile, "sbox", "", "")

	flag.StringVar(&options.keyFile, "k", "", "")
	flag.StringVar(&options.keyFile, "key", "", "")

	flag.StringVar(&options.iv, "i", "", "")
	flag.StringVar(&options.iv, "iv", "", "")

	flag.BoolVar(&options.debug, "debug", false, "")

	flag.Usage = func() {
		printUsage()
		os.Exit(0)
	}

	flag.Parse()

	if encrypt {
		options.operation = operation_encrypt
	} else if decrypt {
		options.operation = operation_decrypt
	} else {
		options.operation = operation_none
	}

	if mac {
		options.computeMac = true

		if options.operation == operation_none {
			options.operation = operation_mac
		}
	}

	options.inFile = flag.Arg(0)
	if len(options.inFile) == 0 {
		printError("Input file not specified\n")
		printUsage()
		os.Exit(1)
	}

	options.outFile = flag.Arg(1)
	if len(options.outFile) == 0 {
		const (
			fileExtEncrypted = ".gost"
			fileExtPlain     = ".plain"
		)

		switch options.operation {
		case operation_encrypt:
			options.outFile = options.inFile + fileExtEncrypted

		case operation_decrypt:
			if options.inFile[len(options.inFile)-5:] == fileExtEncrypted {
				options.outFile = options.inFile[:len(options.inFile)-5]
			} else {
				options.outFile = options.inFile + fileExtPlain
			}
		}
	}

	switch strings.ToLower(mode) {
	case "ecb":
		options.mode = mode_ecb
	case "ctr":
		options.mode = mode_ctr
	case "cfb":
		options.mode = mode_cfb
	default:
		options.mode = mode_none
	}

	if options.operation != operation_mac && options.mode == mode_none {
		if mode == "" {
			options.mode = mode_ctr
		} else {
			printError("Invalid mode: " + mode + "\n")
			printUsage()
			os.Exit(1)
		}
	}

	if len(options.sboxFile) == 0 {
		printError("S-box file not specified\n")
		printUsage()
		os.Exit(1)
	}

	if len(options.keyFile) == 0 {
		printError("Key file not specified\n")
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(
		"Usage: %s [options] <in_file> [out_file]\n\n"+
			"Options:\n"+
			"  -e, -encrypt      Encrypt\n"+
			"  -d, -decrypt      Decrypt\n"+
			"  -a, -mac          Compute a message authentication code\n"+
			"  -m, -mode <mode>  Encryption mode: ecb | ctr | cfb\n"+
			"  -s, -sbox <file>  S-box file\n"+
			"  -k, -key <file>   Key file\n"+
			"  -i, -iv <value>   Initial vector, up to 16 hexadecimal digits\n"+
			"      -debug        Show debug info\n",
		filepath.Base(os.Args[0]),
	)
}

func printError(message string) {
	fmt.Fprintln(os.Stderr, message)
}

func readSbox(cipher *gost89.Gost89, filename string) {
	file, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	buf := make([]byte, 128)
	n, err := file.Read(buf)
	if err != nil && err != io.EOF {
		panic(err)
	}

	if n != 128 {
		printError("Invalid s-box file: " + filename)
		os.Exit(1)
	}

	var sbox [8][16]uint8
	for i := 0; i < 128; i++ {
		sbox[i/16][i%16] = buf[i] % 16
	}

	cipher.SetSbox(sbox)
}

func readKey(cipher *gost89.Gost89, filename string) {
	file, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	buf := make([]byte, 32)
	n, err := file.Read(buf)
	if err != nil && err != io.EOF {
		panic(err)
	}

	if n != 32 {
		printError("Invalid key file: " + filename)
		os.Exit(1)
	}

	cipher.SetKeyBytes(buf)
}

func parseIv(cipher *gost89.Gost89, ivStr string) {
	iv, err := strconv.ParseUint(ivStr, 0, 64)
	if err != nil {
		printError("Invalid initial vector")
		os.Exit(1)
	}

	cipher.SetIv(gost89.Block64{
		uint32(iv & 0xFFFFFFFF),
		uint32(iv >> 32 & 0xFFFFFFFF),
	})
}

func encrypt(cipher *gost89.Gost89, mode int, computeMac bool, inFilename string, outFilename string, progress func(int64, int64)) {
	var f func([]byte) []byte

	switch mode {
	case mode_ecb:
		f = cipher.EncryptBytesECB
	case mode_ctr:
		f = cipher.EncryptBytesCTR
		cipher.InitCTR()
	case mode_cfb:
		f = cipher.EncryptBytesCFB
	}

	ch_read := make(chan []byte, 10)
	ch_read1 := make(chan []byte, 10)
	ch_read2 := make(chan []byte, 10)
	ch_enc := make(chan []byte, 10)
	ch_mac := make(chan bool)
	ch_write := make(chan bool)

	go readFile(inFilename, ch_read, progress)

	if computeMac {
		go func(in chan []byte, out1 chan []byte, out2 chan []byte) {
			for buf := range in {
				out1 <- buf
				out2 <- buf
			}
			close(out1)
			close(out2)
		}(ch_read, ch_read1, ch_read2)

		go func(in chan []byte, out chan []byte) {
			for buf := range in {
				out <- f(buf)
			}
			close(out)
		}(ch_read1, ch_enc)

		go writeFile(outFilename, ch_enc, ch_write)

		go func(in chan []byte, done chan bool) {
			for buf := range in {
				cipher.ComputeMac(buf)
			}
			done <- true
		}(ch_read2, ch_mac)

		<-ch_mac
	} else {
		go func(in chan []byte, out chan []byte) {
			for buf := range in {
				out <- f(buf)
			}
			close(out)
		}(ch_read, ch_enc)

		go writeFile(outFilename, ch_enc, ch_write)
	}

	<-ch_write
}

func decrypt(cipher *gost89.Gost89, mode int, computeMac bool, inFilename string, outFilename string, progress func(int64, int64)) {
	var f func([]byte) []byte

	switch mode {
	case mode_ecb:
		f = cipher.DecryptBytesECB
	case mode_ctr:
		f = cipher.EncryptBytesCTR
		cipher.InitCTR()
	case mode_cfb:
		f = cipher.DecryptBytesCFB
	}

	ch_read := make(chan []byte, 10)
	ch_dec1 := make(chan []byte, 10)
	ch_dec2 := make(chan []byte, 10)
	ch_mac := make(chan bool)
	ch_write := make(chan bool)

	go readFile(inFilename, ch_read, progress)

	if computeMac {
		go func(in chan []byte, out1 chan []byte, out2 chan []byte) {
			for buf := range in {
				plain := f(buf)
				out1 <- plain
				out2 <- plain
			}
			close(out1)
			close(out2)
		}(ch_read, ch_dec1, ch_dec2)

		go writeFile(outFilename, ch_dec1, ch_write)

		go func(in chan []byte, done chan bool) {
			for buf := range in {
				cipher.ComputeMac(buf)
			}
			done <- true
		}(ch_dec2, ch_mac)

		<-ch_mac
	} else {
		go func(in chan []byte, out1 chan []byte) {
			for buf := range in {
				plain := f(buf)
				out1 <- plain
			}
			close(out1)
		}(ch_read, ch_dec1)

		go writeFile(outFilename, ch_dec1, ch_write)
	}

	<-ch_write
}

func computeMac(cipher *gost89.Gost89, filename string, progress func(int64, int64)) {
	cipher.ResetMac()

	ch_read := make(chan []byte, 10)
	ch_mac := make(chan bool)

	go readFile(filename, ch_read, progress)

	go func(in chan []byte, done chan bool) {
		for buf := range in {
			cipher.ComputeMac(buf)
		}
		done <- true
	}(ch_read, ch_mac)

	<-ch_mac
}

func readFile(filename string, out chan []byte, progress func(int64, int64)) {
	file, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	stat, _ := file.Stat()
	size := stat.Size()
	complete := int64(0)

	for {
		progress(complete, size)

		buf := make([]byte, ioBufSize)

		n, err := file.Read(buf)
		if err == io.EOF {
			break
		} else if err != nil {
			panic(err)
		}

		out <- buf[:n]

		complete += int64(n)
	}

	close(out)
}

func writeFile(filename string, in chan []byte, done chan bool) {
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	for buf := range in {
		file.Write(buf)
	}

	done <- true
}

func checkFileExists(filename string) {
	_, err := os.Stat(filename)
	if err != nil {
		printError("File not found: " + filename)
		os.Exit(1)
	}
}
