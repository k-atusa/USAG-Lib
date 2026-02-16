// go test
package Szip

import (
	"fmt"
	"log"
	"os"
	"testing"
)

func TestMain(t *testing.M) {
	// make big file
	if _, err := os.Stat("big.bin"); os.IsNotExist(err) {
		f, err := os.Create("big.bin")
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()

		// 1GB * 5
		chunk := make([]byte, 1024*1024*1024)
		for i := 0; i < 5; i++ {
			if _, err := f.Write(chunk); err != nil {
				log.Fatal(err)
			}
		}
		fmt.Println("big.bin generated.")
	}

	// ZipWriter
	var m ZipWriter
	if err := m.Init("test.zip", true); err != nil {
		log.Fatal(err)
	}
	if err := m.WriteBin("이진 데이터", []byte("Hello, world!")); err != nil {
		log.Fatal(err)
	}
	if err := m.WriteFile("file", "big.bin"); err != nil {
		log.Fatal(err)
	}
	if _, err := m.Close(); err != nil {
		log.Fatal(err)
	}

	// ZipReader
	var r ZipReader
	if err := r.Init("test.zip"); err != nil {
		log.Fatal(err)
	}
	defer r.Close()
	data, err := r.Read(0)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%v %v %s\n", r.Names, r.Sizes, string(data))

	// pack/unpack
	os.Mkdir("pack", 0755)
	os.WriteFile("pack/test.txt", []byte("Hello, world!"), 0644)
	Pack([]string{"pack"}, "t.zip")
	Unpack("t.zip", "pack")
}
