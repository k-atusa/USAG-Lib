// go mod init example.com
// go mod tidy
// go run test.go

package main

import (
	"fmt"

	Bencode "github.com/k-atusa/USAG-Lib/Bencode"
)

func main() {
	text := []byte("안녕하세요, 카투사 프로그래밍 클럽 라이브러리 테스트입니다. Hello, world!")
	dataList := [][]byte{
		{},
		{0x00},
		{0x12, 0x34},
		{0x3f, 0xff},
		{0xff, 0xee, 0xff, 0xff, 0xff, 0xdc, 0xff, 0xff},
		{0xff, 0x00, 0x00, 0x01, 0xff, 0x00, 0x00, 0x01, 0x10},
	}
	var m Bencode.Bencode
	m.Init()

	// Base64 Encode/Decode
	testStr := m.Encode(text, true)
	decoded, _ := m.Decode(testStr)
	fmt.Printf("%s : %s\n", testStr, string(decoded))

	// Base32k Encode/Decode
	testStr = m.Encode(text, false)
	decoded, _ = m.Decode(testStr)
	fmt.Printf("%s : %s\n", testStr, string(decoded))

	// Loop Test
	for _, data := range dataList {
		testStr = m.Encode(data, false)
		decoded, _ = m.Decode(testStr)
		fmt.Printf("%s : %x\n", testStr, decoded)
	}
}
