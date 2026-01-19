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

// ========== Settings ==========
const (
	DATA_SIZE     = 16 * 1048576  // 16 MiB (Hash, Random)
	DATA_SIZE_BIG = 256 * 1048576 // 256 MiB (AES)
	ITER_KDF      = 5             // Slow functions
	ITER_FAST     = 65            // Enc/Dec ops
)

var iterKeyGen = 12 // Variable for RSA-4096 adjustment

func fmtSpeed(size int, d time.Duration) string {
	mb := float64(size) / (1024 * 1024)
	sec := d.Seconds()
	speed := mb / sec
	return fmt.Sprintf("%.2f MiB/s", speed)
}

func fmtTime(count int, d time.Duration) string {
	ms := float64(d.Milliseconds())
	avgMs := ms / float64(count)
	return fmt.Sprintf("%.2f ms/op", avgMs)
}

func main() {
	fmt.Println("=== Bencrypt Performance Benchmark (Go) ===")

	// 1. Random Generation
	start := time.Now()
	Bencrypt.Random(DATA_SIZE)
	dur := time.Since(start)
	fmt.Printf("[Random] Gen: %s\n", fmtSpeed(DATA_SIZE, dur))

	// Prepare Data
	dummyData := make([]byte, DATA_SIZE) // Zero filled

	// 2. SHA3 Functions
	start = time.Now()
	Bencrypt.Sha3256(dummyData)
	dur = time.Since(start)
	fmt.Printf("[SHA3-256]    %s\n", fmtSpeed(DATA_SIZE, dur))

	start = time.Now()
	Bencrypt.Sha3512(dummyData)
	dur = time.Since(start)
	fmt.Printf("[SHA3-512]    %s\n", fmtSpeed(DATA_SIZE, dur))

	fmt.Println("----------------------------------------")

	// 3. KDF Functions
	// PBKDF2
	start = time.Now()
	for i := 0; i < ITER_KDF; i++ {
		Bencrypt.Pbkdf2([]byte("password"), []byte("salt_bytes_16_"), 100000, 64)
	}
	dur = time.Since(start)
	fmt.Printf("[PBKDF2]      %s (iter=100000)\n", fmtTime(ITER_KDF, dur))

	// Argon2
	start = time.Now()
	for i := 0; i < ITER_KDF; i++ {
		Bencrypt.Argon2Hash([]byte("password"), []byte("salt_bytes_16_"))
	}
	dur = time.Since(start)
	fmt.Printf("[Argon2id]    %s (m=256MB, t=3, p=4)\n", fmtTime(ITER_KDF, dur))

	fmt.Println("----------------------------------------")

	// AES Data Prep (256 MB)
	dummyDataBig := make([]byte, DATA_SIZE_BIG)
	var key [44]byte // Zero key

	// 4. AES-GCM (Memory)
	aes := Bencrypt.AES1{}
	aes.Init()

	// Encrypt
	start = time.Now()
	encData, err := aes.EnAESGCM(key, dummyDataBig)
	if err != nil {
		panic(err)
	}
	dur = time.Since(start)
	fmt.Printf("[AES-GCM] Mem Enc: %s\n", fmtSpeed(DATA_SIZE_BIG, dur))

	// Decrypt
	start = time.Now()
	_, err = aes.DeAESGCM(key, encData)
	if err != nil {
		panic(err)
	}
	dur = time.Since(start)
	fmt.Printf("[AES-GCM] Mem Dec: %s\n", fmtSpeed(DATA_SIZE_BIG, dur))

	// 5. AES-GCMx (Memory Stream)
	src := bytes.NewReader(dummyDataBig)
	dst := new(bytes.Buffer)

	start = time.Now()
	err = aes.EnAESGCMx(key, src, DATA_SIZE_BIG, dst, 0)
	if err != nil {
		panic(err)
	}
	dur = time.Since(start)
	fmt.Printf("[AES-GCMx] Mem Enc: %s\n", fmtSpeed(DATA_SIZE_BIG, dur))

	encStreamData := dst.Bytes()
	src = bytes.NewReader(encStreamData)
	dst.Reset()

	start = time.Now()
	err = aes.DeAESGCMx(key, src, len(encStreamData), dst, 0)
	if err != nil {
		panic(err)
	}
	dur = time.Since(start)
	fmt.Printf("[AES-GCMx] Mem Dec: %s\n", fmtSpeed(DATA_SIZE_BIG, dur))

	// 6. AES-GCMx (File Stream)
	tempDir, err := os.MkdirTemp("", "bench_go")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tempDir) // Cleanup

	fSrcPath := filepath.Join(tempDir, "source.bin")
	fDstPath := filepath.Join(tempDir, "dest.bin")
	fDecPath := filepath.Join(tempDir, "decrypted.bin")

	// Create dummy file
	err = os.WriteFile(fSrcPath, dummyDataBig, 0644)
	if err != nil {
		panic(err)
	}

	// Encrypt File
	fSrc, _ := os.Open(fSrcPath)
	fDst, _ := os.Create(fDstPath)
	start = time.Now()
	err = aes.EnAESGCMx(key, fSrc, DATA_SIZE_BIG, fDst, 0)
	if err != nil {
		panic(err)
	}
	dur = time.Since(start)
	fSrc.Close()
	fDst.Close()
	fmt.Printf("[AES-GCMx] File Enc: %s\n", fmtSpeed(DATA_SIZE_BIG, dur))

	// Decrypt File
	fEncInfo, _ := os.Stat(fDstPath)
	encSize := int(fEncInfo.Size())

	fDstRead, _ := os.Open(fDstPath)
	fDec, _ := os.Create(fDecPath)
	start = time.Now()
	err = aes.DeAESGCMx(key, fDstRead, encSize, fDec, 0)
	if err != nil {
		panic(err)
	}
	dur = time.Since(start)
	fDstRead.Close()
	fDec.Close()
	fmt.Printf("[AES-GCMx] File Dec: %s\n", fmtSpeed(DATA_SIZE_BIG, dur))

	fmt.Println("----------------------------------------")

	// 7. RSA
	payload := make([]byte, 64)
	for i := range payload {
		payload[i] = 'A'
	}
	bitSizes := []int{2048, 4096}

	for _, bits := range bitSizes {
		if bits == 4096 {
			iterKeyGen = 2
		}

		rsa := Bencrypt.RSA1{}

		// Key Gen
		start = time.Now()
		for i := 0; i < iterKeyGen; i++ {
			_, _, err = rsa.Genkey(bits)
			if err != nil {
				panic(err)
			}
		}
		dur = time.Since(start)
		fmt.Printf("[RSA-%d] GenKey : %s\n", bits, fmtTime(iterKeyGen, dur))

		// Prepare for Enc/Dec
		rsa.Genkey(bits) // Ensure keys are loaded in struct
		var enc []byte

		// Encrypt
		start = time.Now()
		for i := 0; i < ITER_FAST; i++ {
			enc, err = rsa.Encrypt(payload)
			if err != nil {
				panic(err)
			}
		}
		dur = time.Since(start)
		fmt.Printf("[RSA-%d] Encrypt: %s\n", bits, fmtTime(ITER_FAST, dur))

		// Decrypt
		start = time.Now()
		for i := 0; i < ITER_FAST; i++ {
			_, err = rsa.Decrypt(enc)
			if err != nil {
				panic(err)
			}
		}
		dur = time.Since(start)
		fmt.Printf("[RSA-%d] Decrypt: %s\n", bits, fmtTime(ITER_FAST, dur))
		fmt.Printf("[RSA-%d] Sign   : (Similar to Decrypt)\n", bits)
	}

	fmt.Println("----------------------------------------")
	iterKeyGen = 20

	// 8. ECC (Curve448)
	ecc := Bencrypt.ECC1{}

	// Key Gen
	start = time.Now()
	for i := 0; i < iterKeyGen; i++ {
		_, _, err = ecc.Genkey()
		if err != nil {
			panic(err)
		}
	}
	dur = time.Since(start)
	fmt.Printf("[ECC-448]  GenKey : %s\n", fmtTime(iterKeyGen, dur))

	// Prepare
	pubBytes, _, _ := ecc.Genkey()
	var eccEnc []byte

	// Encrypt
	start = time.Now()
	for i := 0; i < ITER_FAST; i++ {
		eccEnc, err = ecc.Encrypt(payload, pubBytes)
		if err != nil {
			panic(err)
		}
	}
	dur = time.Since(start)
	fmt.Printf("[ECC-448]  Encrypt: %s (Includes AES gen)\n", fmtTime(ITER_FAST, dur))

	// Decrypt
	start = time.Now()
	for i := 0; i < ITER_FAST; i++ {
		_, err = ecc.Decrypt(eccEnc)
		if err != nil {
			panic(err)
		}
	}
	dur = time.Since(start)
	fmt.Printf("[ECC-448]  Decrypt: %s (Includes AES gen)\n", fmtTime(ITER_FAST, dur))
}
