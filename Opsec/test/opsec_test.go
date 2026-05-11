// go test
package Opsec

import (
	"bytes"
	"fmt"
	"testing"

	Bencrypt "github.com/k-atusa/USAG-Lib/Bencrypt"
)

func TestMain(t *testing.T) {
	fmt.Println("=== Opsec Module Test Start ===")

	// 1. CRC32, Pad Test
	crc := Crc32([]byte("test"))
	fmt.Printf("[CRC32 Test] 'test' -> %s (Expected: 0c7e7fd8)\n", crc)
	if crc != "0c7e7fd8" {
		t.Errorf("CRC32 validation failed")
	}
	for _, size := range []int64{0, 1024, 12 * 1048576, 123456789, 2147483647, 8 * 1073741824} {
		fmt.Printf("%d -> %d\n", size, PadLen(size)+size)
		if size < 512*1048576 {
			var f bytes.Buffer
			PadFile(&f, size)
			fmt.Println(f.Len() == int(size))
		}
	}

	// 2. Read/Write Stream Test
	var w bytes.Buffer
	w.Write(make([]byte, 128*4))

	m := new(Opsec)
	m.Reset()
	err := m.Write(&w, []byte("Hello, world!"))
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}

	r := bytes.NewReader(w.Bytes())
	readBack, err := m.Read(r, 65535)
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	fmt.Printf("[Read Test] Content: %s\n", string(readBack))

	// test parameters
	msg := "msg-test"
	smsg := "smsg-test"
	sinf := []byte("sinf-test")
	bodyalgo := "gcmx1"
	var bodysize int64 = 1048576
	bodyinfo := []byte("binf-test")

	// 3. pw-mode (sha3, pbk2, arg2)
	fmt.Println("\n--- pw-mode tests (sha3, pbk2, arg2) ---")
	pwMethods := []string{"sha3", "pbk2", "arg2"}
	for _, method := range pwMethods {
		m.Reset()
		m.Msg = msg
		m.Smsg = smsg
		m.SmsgInfo = sinf
		m.BodyAlgo = bodyalgo
		m.BodySize = bodysize
		m.BodyInfo = bodyinfo

		enc, err := m.Encpw(method, []byte("password"), []byte("keyfile"))
		if err != nil {
			t.Errorf("[%s] Encpw Error: %v", method, err)
			continue
		}

		// get BodyKey
		bodykey := make([]byte, len(m.BodyKey))
		copy(bodykey, m.BodyKey)

		m.View(enc)
		err = m.Decpw([]byte("password"), []byte("keyfile"))
		if err != nil {
			t.Errorf("[%s] Decpw Error: %v", method, err)
		}

		fmt.Println(method)
		b1 := msg == m.Msg
		b2 := smsg == m.Smsg
		b3 := bytes.Equal(sinf, m.SmsgInfo)
		b4 := bodyalgo == m.BodyAlgo
		b5 := bodysize == m.BodySize
		b6 := bytes.Equal(bodyinfo, m.BodyInfo)
		b7 := bytes.Equal(bodykey, m.BodyKey)

		formatResult := func(b bool) string {
			if b {
				return "OK"
			}
			return "FAIL"
		}
		fmt.Printf("%s %s %s %s %s %s %s\n",
			formatResult(b1), formatResult(b2), formatResult(b3),
			formatResult(b4), formatResult(b5), formatResult(b6), formatResult(b7))
	}

	// 4. pub-mode (rsa1, rsa2, ecc1, pqc1)
	fmt.Println("\n--- pub-mode tests (rsa1, rsa2, ecc1, pqc1) ---")
	pubMethods := []string{"rsa1", "rsa2", "ecc1", "pqc1"}
	for _, method := range pubMethods {
		me := new(Bencrypt.AsymMaster)
		me.Init(method)
		myPub, myPri, err := me.Genkey()
		if err != nil {
			t.Fatalf("[%s] Key generation error (me): %v", method, err)
		}

		peer := new(Bencrypt.AsymMaster)
		peer.Init(method)
		peerPub, peerPri, err := peer.Genkey()
		if err != nil {
			t.Fatalf("[%s] Key generation error (peer): %v", method, err)
		}

		m.Reset()
		m.Msg = msg
		m.Smsg = smsg
		m.SmsgInfo = sinf
		m.BodyAlgo = bodyalgo
		m.BodySize = bodysize
		m.BodyInfo = bodyinfo

		enc, err := m.Encpub(method, myPub, peerPri)
		if err != nil {
			t.Errorf("[%s] Encpub Error: %v", method, err)
			continue
		}

		bodykey := make([]byte, len(m.BodyKey))
		copy(bodykey, m.BodyKey)

		m.View(enc)
		err = m.Decpub(myPri, myPub, peerPub)
		if err != nil {
			t.Errorf("[%s] Decpub Error: %v", method, err)
		}

		fmt.Println(method)
		b1 := msg == m.Msg
		b2 := smsg == m.Smsg
		b3 := bytes.Equal(sinf, m.SmsgInfo)
		b4 := bodyalgo == m.BodyAlgo
		b5 := bodysize == m.BodySize
		b6 := bytes.Equal(bodyinfo, m.BodyInfo)
		b7 := bytes.Equal(bodykey, m.BodyKey)

		formatResult := func(b bool) string {
			if b {
				return "OK"
			}
			return "FAIL"
		}
		fmt.Printf("%s %s %s %s %s %s %s\n",
			formatResult(b1), formatResult(b2), formatResult(b3),
			formatResult(b4), formatResult(b5), formatResult(b6), formatResult(b7))
	}

	// 5. Masker Test
	fmt.Println("\n--- Masker Test ---")
	mA := GetMasker(8)
	mB := GetMasker(8)
	key := Bencrypt.Random(8753)
	maskedZero, _ := mA.XOR([]byte{0, 0, 0, 0})
	fmt.Printf("%x\n", maskedZero)
	maskedKey, _ := mA.XOR(key)
	restoredKey, _ := mB.XOR(maskedKey)
	fmt.Println(bytes.Equal(restoredKey, key))

	fmt.Println("\n=== All tests completed ===")
}
