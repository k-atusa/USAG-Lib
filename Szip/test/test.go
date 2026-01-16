// go mod init example.com
// go mod tidy
// go run test.go

package main

import (
	"fmt"
	"log"
	"os"

	Szip "github.com/k-atusa/USAG-Lib/Szip"
)

func main() {
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
	m := &Szip.ZipWriter{}
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
	r := &Szip.ZipReader{}
	if err := r.Init("test.zip"); err != nil {
		log.Fatal(err)
	}
	defer r.Close()
	data, err := r.Read(0)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%v %v %s\n", r.Names, r.Sizes, string(data))
}
