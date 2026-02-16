// go test
package Icons

import (
	"os"
	"testing"
)

func TestMain(t *testing.M) {
	os.WriteFile("zip.png", ZipPng, 0644)
	os.WriteFile("zip.webp", ZipWebp, 0644)
	os.WriteFile("aes.png", AesPng, 0644)
	os.WriteFile("aes.webp", AesWebp, 0644)
	os.WriteFile("cloud.png", CloudPng, 0644)
	os.WriteFile("cloud.webp", CloudWebp, 0644)
}
