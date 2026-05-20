// go test
package Bencrypt

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	// load testsheet.txt
	fileBytes, err := os.ReadFile("testsheet.txt")
	if err != nil {
		panic(err)
	}
	lines := strings.Split(strings.ReplaceAll(string(fileBytes), "\r\n", "\n"), "\n")
	var sheet [][]byte
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		dec, err := base64.StdEncoding.DecodeString(line)
		if err == nil {
			sheet = append(sheet, dec)
		}
	}
	pos := 0

	// ========== Basic function test ==========
	fmt.Println("testing basic functions...")
	data := []byte("0000")
	fmt.Println(base64.StdEncoding.EncodeToString(Random(16)))
	fmt.Println(base64.StdEncoding.EncodeToString(SHA3256(data))) // pq9wt68/QjUteD6LB1FeQzw9RWadTv7mcFFnJxk7KRs=
	fmt.Println(base64.StdEncoding.EncodeToString(SHA3512(data))) // tnjOmGIvYntbNcoej2VvG9M1RdJCtZ8BWjHek4r6OvvmhThbjjzJ/zfYwq+G7r/TGe7WWr20vkGBzULuTzcPYQ==

	// ========== Masker test ==========
	fmt.Println("testing Masker...")
	mA := GetMasker(8)
	mB := GetMasker(8)
	maskedZero, _ := mA.XOR([]byte{0, 0, 0, 0})
	fmt.Printf("%x\n", maskedZero)
	testkey := Random(8753)
	maskedKey, _ := mA.XOR(testkey)
	restoredKey, _ := mB.XOR(maskedKey)
	fmt.Println(bytes.Equal(restoredKey, testkey))
	testkey = Random(16384)
	maskedKey, _ = mA.XOR(testkey)
	restoredKey, _ = mB.XOR(maskedKey)
	fmt.Println(bytes.Equal(restoredKey, testkey))

	// ========== HashMaster test ==========
	fmt.Println("testing HashMaster...")
	hashm := []string{"sha3", "pbk2", "arg2"}
	pw := []byte("ABCDABCDABCDABCD")
	salt := []byte("1234123412341234")

	for _, algo := range hashm {
		w := new(HashMaster)
		w.Init(algo, 0, 0) // set default
		pwst, keygen, _ := w.KDF(pw, salt)

		fmt.Println(bytes.Equal(sheet[pos], pwst))
		pos++
		fmt.Println(bytes.Equal(sheet[pos], keygen))
		pos++
	}

	// ========== SymMaster test ==========
	fmt.Println("testing SymMaster...")
	symm := []string{"gcm1", "gcmx1"}
	key := bytes.Repeat([]byte("0"), 44)
	plainSym := bytes.Repeat([]byte("Hello, world!"), 32)

	for _, algo := range symm {
		w := new(SymMaster)
		w.Init(algo, key)

		// DeBin test
		deBinRes, _ := w.DeBin(sheet[pos])
		fmt.Println(bytes.Equal(plainSym, deBinRes))
		pos++

		// DeFile test
		tempDec := new(bytes.Buffer)
		w.DeFile(bytes.NewReader(sheet[pos]), int64(len(sheet[pos])), tempDec)
		fmt.Println(bytes.Equal(plainSym, tempDec.Bytes()))
		pos++

		// 10MB big data test
		bigdata := make([]byte, 10000000) // 10MB null bytes

		// EnBin/DeBin test
		bigenc, _ := w.EnBin(bigdata)
		bigdec, _ := w.DeBin(bigenc)
		fmt.Println(bytes.Equal(bigdata, bigdec))

		// 10MB big file test
		tempEncFile := new(bytes.Buffer)
		w.EnFile(bytes.NewReader(bigdata), int64(len(bigdata)), tempEncFile)
		bigencFileBytes := tempEncFile.Bytes()

		tempDecFile := new(bytes.Buffer)
		w.DeFile(bytes.NewReader(bigencFileBytes), int64(len(bigencFileBytes)), tempDecFile)
		fmt.Println(bytes.Equal(bigdata, tempDecFile.Bytes()))
	}

	// ========== AsymMaster test ==========
	fmt.Println("testing AsymMaster...")
	asymm := []string{"rsa1", "rsa2", "ecc1", "pqc1"}
	plainAsym := []byte("Hello, world!")

	for _, algo := range asymm {
		w := new(AsymMaster)
		w.Init(algo)

		pub := sheet[pos]
		pri := sheet[pos+1]
		pos += 2
		w.Loadkey(pub, pri)

		enc := sheet[pos]
		sign := sheet[pos+1]
		pos += 2

		// cross-test with Python implementation
		decRes, _ := w.Decrypt(enc)
		fmt.Println(bytes.Equal(plainAsym, decRes))
		fmt.Println(w.Verify(plainAsym, sign))

		// generate new key pair
		temp := new(AsymMaster)
		temp.Init(algo)
		tPub, tPri, _ := temp.Genkey()

		a := new(AsymMaster)
		a.Init(algo)
		a.Loadkey(tPub, nil)

		b := new(AsymMaster)
		b.Init(algo)
		b.Loadkey(nil, tPri)

		// A encrypt -> B decrypt
		tEnc, _ := a.Encrypt(plainAsym)
		tDec, _ := b.Decrypt(tEnc)
		fmt.Println(bytes.Equal(plainAsym, tDec))

		// B sign -> A verify
		tSign, _ := b.Sign(plainAsym)
		fmt.Println(a.Verify(plainAsym, tSign))
	}
}
