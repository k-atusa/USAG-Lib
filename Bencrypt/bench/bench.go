// go mod init example.com
// go mod tidy
// go run bench.go

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"

	Bencrypt "github.com/k-atusa/USAG-Lib/Bencrypt"
)

func fmtSpeed(sizeBytes int64, duration time.Duration) string {
	mb := float64(sizeBytes) / (1024.0 * 1024.0)
	speed := mb / duration.Seconds()
	return fmt.Sprintf("%.2f MiB/s", speed)
}

func fmtTime(count int, duration time.Duration) string {
	avgMs := (duration.Seconds() / float64(count)) * 1000.0
	return fmt.Sprintf("%.2f ms/op", avgMs)
}

func main() {
	fmt.Println("Bencrypt Benchmarks (Go)")

	time.Sleep(1 * time.Second)
	fmt.Println("\n\n===== Basic Functions =====")
	p := []int64{100 * 1048576, 100 * 1048576, 100 * 1048576} // 100 MiB

	start := time.Now()
	Bencrypt.Random(int(p[0]))
	fmt.Printf("RandGen: %s\n", fmtSpeed(p[0], time.Since(start)))

	dataBasic := make([]byte, p[1])
	start = time.Now()
	Bencrypt.SHA3256(dataBasic)
	fmt.Printf("SHA3256: %s\n", fmtSpeed(p[1], time.Since(start)))

	dataBasic = make([]byte, p[2])
	start = time.Now()
	Bencrypt.SHA3512(dataBasic)
	fmt.Printf("SHA3512: %s\n", fmtSpeed(p[2], time.Since(start)))

	time.Sleep(1 * time.Second)
	fmt.Println("\n\n===== Hash Functions =====")
	hashAlgos := []string{"sha3", "pbk2", "arg2"}
	itersH := []int{100000, 5, 5}
	pw := make([]byte, 64)   // std: 64B password
	salt := make([]byte, 32) // std: 32B salt

	for i, algo := range hashAlgos {
		w := new(Bencrypt.HashMaster)
		w.Init(algo, 32, 44)
		start = time.Now()
		for j := 0; j < itersH[i]; j++ {
			w.KDF(pw, salt)
		}
		fmt.Printf("%s: %s\n", algo, fmtTime(itersH[i], time.Since(start)))
	}

	time.Sleep(1 * time.Second)
	fmt.Println("\n\n===== Symmetric Functions =====")
	fsize := int64(512 * 1048576) // 512 MiB
	symData := make([]byte, fsize)

	// Create temp file for file benchmark
	tempBinPath := filepath.Join(".", "temp.bin")
	tempOutPath := filepath.Join(".", "temp.out")
	tempBin, _ := os.Create(tempBinPath)
	ffBlock := bytes.Repeat([]byte{0xff}, 1048576) // 1 MiB chunk
	for i := 0; i < 512; i++ {
		tempBin.Write(ffBlock)
	}
	tempBin.Close()

	symAlgos := []string{"gcm1", "gcmx1"}
	symKey := bytes.Repeat([]byte("0"), 44) // 44B Null Key

	for _, algo := range symAlgos {
		w := new(Bencrypt.SymMaster)
		w.Init(algo, symKey)

		// In-memory test
		start = time.Now()
		w.EnBin(symData)
		fmt.Printf("%s (in-memory): %s\n", algo, fmtSpeed(fsize, time.Since(start)))

		// File test
		inFile, _ := os.Open(tempBinPath)
		outFile, _ := os.Create(tempOutPath)

		start = time.Now()
		w.EnFile(inFile, fsize, outFile)
		dur := time.Since(start)

		inFile.Close()
		outFile.Close()
		fmt.Printf("%s (file): %s\n", algo, fmtSpeed(fsize, dur))
		fmt.Println()
	}

	time.Sleep(1 * time.Second)
	fmt.Println("\n\n===== Asymmetric Functions =====")
	asymAlgos := []string{"rsa1", "rsa2", "ecc1", "pqc1"}
	itersG := []int{3, 1, 20, 20}
	itersC := []int{25, 25, 50, 50}
	asymData := make([]byte, 64) // std: 64B data

	for i, algo := range asymAlgos {
		w := new(Bencrypt.AsymMaster)
		w.Init(algo)

		// GenKey Test
		start = time.Now()
		for j := 0; j < itersG[i]; j++ {
			w.Genkey()
		}
		fmt.Printf("%s (genkey): %s\n", algo, fmtTime(itersG[i], time.Since(start)))

		// Encrypt Test
		start = time.Now()
		for j := 0; j < itersC[i]; j++ {
			w.Encrypt(asymData)
		}
		fmt.Printf("%s (encrypt): %s\n", algo, fmtTime(itersC[i], time.Since(start)))

		// Sign Test
		start = time.Now()
		for j := 0; j < itersC[i]; j++ {
			w.Sign(asymData)
		}
		fmt.Printf("%s (sign): %s\n", algo, fmtTime(itersC[i], time.Since(start)))
		fmt.Println()
	}

	// Clean-up
	time.Sleep(1 * time.Second)
	os.Remove(tempBinPath)
	os.Remove(tempOutPath)
}
