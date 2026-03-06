// go test
package Bencode

import (
	"fmt"
	"testing"
)

func TestMain(t *testing.T) {
	b, _ := Decode64(Encode64([]byte("")))
	fmt.Println(string(b))
	b, _ = Decode64(Encode64([]byte("abc")))
	fmt.Println(string(b))
	b, _ = Decode64(Encode64([]byte("라이브러리 테스트 코드입니다.")))
	fmt.Println(string(b))
}
