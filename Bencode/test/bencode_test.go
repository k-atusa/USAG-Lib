// go test
package Bencode

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestMain(t *testing.T) {
	data := [4][]byte{}
	data[1] = []byte("abc")
	data[2] = []byte("라이브러리 테스트 코드입니다.")
	data[3] = []byte(strings.Repeat("ABCD", 64))

	s := ""
	var d []byte
	for _, r := range data {
		s, _ = Encode64(r, "", 0, 0)
		d, _ = Decode64(s, "")
		fmt.Println(s)
		fmt.Println(bytes.Equal(r, d))
		s, _ = Encode64(r, "#", 8, 3)
		d, _ = Decode64(s, "#")
		fmt.Println(s)
		fmt.Println(bytes.Equal(r, d))
	}
}
