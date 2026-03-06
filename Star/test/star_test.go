// go test
package Star

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestMain(t *testing.T) {
	// Create dummy file for test
	dummyName := "small.bin"
	if _, err := os.Stat(dummyName); os.IsNotExist(err) {
		f, _ := os.Create(dummyName)
		zeroes := make([]byte, 1024*1024)
		for i := 0; i < 100; i++ {
			f.Write(zeroes)
		}
		f.Close()
	}
	fmt.Println("--- Start Go Test ---")

	// TarWriter
	var mw TarWriter
	mw.Init("") // memory output

	mw.WriteDir("test/", 0755) // Dir
	longName := "test/" + strings.Repeat("가", 100) + "파일.bin"
	mw.WriteFile(longName, dummyName, 0644)              // Long File
	mw.WriteBin("이진 데이터", []byte("Hello, world!"), 0644) // Binary

	tarData, _ := mw.Close()
	os.WriteFile("test.tar", tarData, 0644)
	fmt.Println("Created test.tar")

	// TarReader
	var mr TarReader
	mr.Init("test.tar")
	defer mr.Close()
	for mr.Next() {
		fmt.Printf("Name: %s, Size: %d, Mode: %o, IsDir: %v\n", mr.Name, mr.Size, mr.Mode, mr.IsDir)
		if mr.IsDir {
			mr.Mkfile(mr.Name)
		} else if mr.Size < 100 {
			fmt.Printf("Data: %s\n", string(mr.Read()))
		} else {
			mr.Mkfile("output.bin")
		}
	}

	// pack/unpack
	os.Mkdir("pack", 0755)
	os.WriteFile("pack/test.txt", []byte("Hello, world!"), 0644)
	Pack([]string{"pack"}, "t.tar")
	Unpack("t.tar", "pack")
}
