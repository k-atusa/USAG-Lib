// go test
package Opsec

import (
	"bytes"
	"fmt"
	"log"
	"testing"

	Bencrypt "github.com/k-atusa/USAG-Lib/Bencrypt"
)

func TestMain(t *testing.T) {
	// 1. CRC32 Test
	fmt.Println(Crc32([]byte("test"))) // Expected: 0c7e7fd8

	// 2. Key Generation
	rsa := new(Bencrypt.RSA1)
	pub0, pri0, err := rsa.Genkey(2048)
	if err != nil {
		log.Fatal(err)
	}
	ecc := new(Bencrypt.ECC1)
	pub1, pri1, err := ecc.Genkey()
	if err != nil {
		log.Fatal(err)
	}
	m := new(Opsec)

	// 3. Read/Write Test
	var w bytes.Buffer
	w.Write(make([]byte, 128*4))
	err = m.Write(&w, []byte("Hello, world!"))
	if err != nil {
		log.Fatal(err)
	}

	// Read back
	r := bytes.NewReader(w.Bytes())
	readBack, err := m.Read(r, 65535)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(readBack)) // Expected: Hello, world!

	// 4. PBKDF2 Test
	m.Msg = "msg-test"
	m.Smsg = "smsg-test"
	m.Size = 1024
	m.Name = "name-test"
	m.BodyAlgo = "gcm1"
	m.ContAlgo = "zip1"

	encPbk, err := m.Encpw("pbk1", []byte("password"), []byte("keyfile"))
	if err != nil {
		log.Fatal(err)
	}
	m.View(encPbk)
	err = m.Decpw([]byte("password"), []byte("keyfile"))
	if err != nil {
		log.Fatal(err)
	}
	printStatus(m)
	m.Reset()

	// 5. Argon2 Test
	m.Msg = "msg-test"
	m.Smsg = "smsg-test"

	encArg, err := m.Encpw("arg1", []byte("password"), nil)
	if err != nil {
		log.Fatal(err)
	}
	m.View(encArg)
	err = m.Decpw([]byte("password"), nil)
	if err != nil {
		log.Fatal(err)
	}
	printStatus(m)
	m.Reset()

	// 6. RSA Test
	m.Msg = "msg-test"
	m.Smsg = "smsg-test"
	m.Size = 1024
	m.Name = "name-test"
	m.BodyAlgo = "gcm1"
	m.ContAlgo = "zip1"

	encRSA, err := m.Encpub("rsa1", pub0, pri0)
	if err != nil {
		log.Fatal(err)
	}
	m.View(encRSA)
	err = m.Decpub(pri0, pub0)
	if err != nil {
		log.Fatal(err)
	}
	printStatus(m)
	m.Reset()

	// 7. ECC Test
	m.Msg = "msg-test"
	m.Smsg = "smsg-test"

	encECC, err := m.Encpub("ecc1", pub1, pri1)
	if err != nil {
		log.Fatal(err)
	}
	m.View(encECC)
	err = m.Decpub(pri1, pub1)
	if err != nil {
		log.Fatal(err)
	}
	printStatus(m)
}

// Helper to print object status
func printStatus(m *Opsec) {
	fmt.Printf("%s %s %d %s %s %s %d\n",
		m.Msg,
		m.Smsg,
		m.Size,
		m.Name,
		m.BodyAlgo,
		m.ContAlgo,
		len(m.BodyKey),
	)
}
