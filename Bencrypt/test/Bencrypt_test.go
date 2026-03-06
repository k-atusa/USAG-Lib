// go test
package Bencrypt

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

const (
	pub0  = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApCITGWNQcB8GdwWFpKW02VVYdtir1/IAbUstmwhBugo2rbdi1a/7n/hafglvwV+kxQ4jJychYjl921OhPwqlaFv/+iP8sDemmjXKW5G9QtSGFx34FVLYGewrF1ApoyvI5Zi3m7KBhrAFQyZ+6VYojnx0NJPjnCOGwSx8rb73Csi+gBoxSse5EUUwywWJ9tQkQfayFY7bVAORje7y58rrk4ASwpGNnaXgsNQffCgtBf6J4XhXm/neZP7wpDJqx6j4c5JY0OnYnCIkU66RMgEn4jHc+hg9Hfr99AWBnxjuMrAUbsaDrHrAcl5Sxhi0xzlxFvT+/PFx0BzPSt/noM0C1wIDAQAB"
	pri0  = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCkIhMZY1BwHwZ3BYWkpbTZVVh22KvX8gBtSy2bCEG6Cjatt2LVr/uf+Fp+CW/BX6TFDiMnJyFiOX3bU6E/CqVoW//6I/ywN6aaNcpbkb1C1IYXHfgVUtgZ7CsXUCmjK8jlmLebsoGGsAVDJn7pViiOfHQ0k+OcI4bBLHytvvcKyL6AGjFKx7kRRTDLBYn21CRB9rIVjttUA5GN7vLnyuuTgBLCkY2dpeCw1B98KC0F/onheFeb+d5k/vCkMmrHqPhzkljQ6dicIiRTrpEyASfiMdz6GD0d+v30BYGfGO4ysBRuxoOsesByXlLGGLTHOXEW9P788XHQHM9K3+egzQLXAgMBAAECggEAAOL2O3Lf4lsoi8gJ2sPSYEInwiyVcQsrmWuIiYfX4wtfFD0jWYgj0c9jnb6rTd4YY8AZzIJXmdI5rc+b1V1XW2Lz1QQQv1rtmXOk7i2xWgUP3FwbFPJnnGw8J1oVf34jDapvg3XJYVLeFGjG0rfWbD6b2hTaa+N9PNniqoWXjAVbWp2yJ0emN2nyFF/jhXIKJHmJZFAe4DFp/vHLykxHKOtMxsoHikjRj3KnpPy2NQzZue8jQ6UvX1zZhucR9tJb+9kVq9nLVxKVinSvaq8hLavtEh74o0ykQzxr4bT+eeX+6Jm0vON7VCH+HmeKdrACnsZ5tKd4oCA+2EXw2cPPMQKBgQDELGPJHQH0SxSjOyaXkKoSf2jvxYCQiay6Y+qT6lnL7Ag9MtOOGLARezaV8fYRBwTYdIUKCJj8jZtzTJVmg30t1qyy1jTkzwlq36cWxzToaQPYZVULuHOWMyMcUPdgLk+kslVxN7ZyhpDxdatAcnr4HphAsD20F+Dk0ZJASDU0kwKBgQDWMD3OKZOC661NsSjI7+INDIxov8aP/MBJKirj+/I9KU4cXfvzuMS/G20EvI9Bxc294Aghnp/I25Eg9NTL8AzWCJlXM4AF+fzM8yR/NlW/nfxOT07wHbvKMTQHM3bBcIKQkg3BCCIomGf0jWthXRROdWaFE3G7HksfnOS0k2pHLQKBgQC/2d24yKqpnGfRfz6tyafaMUqR+2hRcqM/Igo+oFkzamFgYH2vIQvH/OUUXa7VVjTx73pQprnffCnD5+jQedWJZ8I7n+vYvXWrVJEXYLiodlNxZSB4NuqrwNUckz5qjMANBO80q1S9ykakLfzOKWeDkoA5+2JM53FktmQ+g5+tCwKBgFnjhQywhie7oM+qOeOaSNQRIBwV388t08Tg3X8wjUj9vLpK9yIhuPA7IlWKjNSdnurAyqjRWV2CSDX8ihHMfJaWpUPjaScY8u9QW1DIDNSOCQUUY5yB3f3NCHi9MGmePi1OHleUgkFnNLl9YENMPOlwe8X9kw1keUKbJaBi/YdBAoGAWQ+zica3FnZI5oTEv44qh/S0hbjHjo3AhST+5VTOx7pitwySI8gC2u1af5fHJskBEwQKhkvOt1n7eh88aLo3b7HHB4QIur+KFrKmUvBHIa3Y2FQOTsBQj1Cj9hMTWBErqEb/+/D9n5PlH7zt5MVwZTA8HAGUpVhIR3xxUtpTiJI="
	enc0  = "nCFhvHbvIbAYlk8MpjVd5hmQHrbm3kVc/heznSujIV4xsofvYpxUntktOppBDHMlxoqDSS8KKOw7uC6mnzPjjNAzGY4UWBvakegqEsWVSfiGouh8sNJyMyx5dsc8dk4j2IDe8gNqE/l04cddtrfVSgRle82FJOKvSNyAfI0bJPooj1WJJIXa+LdEiP5EY8y7ccIP+2T5rTqHUHNkjzlUGZOr+6Mkj6eVgfJKhtKhw3tt7tLM/HF8NbBNPRSGO8cHEVuHMke0JLaRHc68qpE3vKT/GCxveJC5L7T5wxiX9KOwB6zr9fWaVxfTiEDGU4IdUZgyeZOAEXY9V19uFExLAw=="
	sign0 = "WagxpWpmGUK2vtx1Vjf1Bn67FHwdNy5co9uMV2SV9ZI6KCOYl/QWfA5oF9qIhb58lY00RVzUE+GiqQozGuAE9KIK70icBlWB1bq5azcBbR1sRDycLldT8HZPTyDdnW+pC/D0lvAWA99xVNSk5mEaJn1FKPbCAJwTrJZY5UQTF0XM8vWFUW2JQtlYLVQgcpALY6HYgOVSaXAaAEifftOurRBncn7BAudwIIv4OL5kBbXciEDlHO5aHDC3I0GG3zVhKA0BousFC2V+fiLYfH73i7K1rXIb5uhopSKhi82tRgII9rxWACwV3n3fOTSaNWvGHwZKIXvQChpRQHcBFomZcg=="
	pub1  = "8Gjuhn7QRfAUkKEswjJXCxP+znZnp2oO8mZFHOaHs+0eHb9CnyC6JfScgAMBZB/dGY695aIHu/iY4CNGMcshZ1AxZzPs45kaCb2ZbJIAXM2VuNwdUJG3gmCYqAbRFNJSWTKZu2mFuJW/SiDLccf48YA="
	pri1  = "7CLpb2gjTtPzLhAgEcPx2WBeuTDo1K3PGKG891IlmWzCARYbBm/pGQoG5szSqyf/0kGfYc38zOCFJM1kpZ7kKUi1jdqCUUKHXqTW9gr3ppRHQkrjlE0h2k29jrRbBxPfSgILf82roc417N3krf5JiXA="
	enc1  = "OENn7kZfuSIzkrtcAy+qUGM9no4Ra8Wd7HCIY66OOfBTcETHNBkHftaMdZfWTMHj3UkUbtRQpwIoCBYHE8fygKJE9oRtAhMM2cbMBmY="
	sign1 = "eZGi/aYQQKnR8LXtgIcaPWq+rYnq/MYpyrbJ+vjyVR83iL3eX3D3sFvTJ0SCRe5dJMoUBXxW+tAASLxmf0KHs2AeGUeo/IWLOrbwmQhxqegKmzJuOrnw7nMSv6BamvKD3/BkDKaoQiFDCq25E2nlDCIA"
)

func b64d(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func p(d []byte) {
	if d == nil {
		return
	}
	for _, b := range d {
		fmt.Printf("%d ", b)
	}
	fmt.Println("\n====================")
}

func TestMain(t *testing.T) {
	// ===== basic test =====
	fmt.Println("\n===== basic test =====")
	p(Random(16))
	p(SHA3256([]byte{}))
	p(SHA3512([]byte{}))

	// ===== basic-adv test =====
	fmt.Println("\n===== basic-adv test =====")
	p(Pbkdf2([]byte("0000"), []byte("0000000000000000"), 0, 0))

	tHash := Argon2Hash([]byte("0000"), []byte("0000000000000000"))
	fmt.Println(tHash)
	fmt.Println(Argon2Verify(tHash, []byte("0000")))

	gk, _ := Genkey([]byte("0000000000000000"), "test", 16)
	p(gk)

	// ===== sym-gcm1 test =====
	fmt.Println("\n===== sym-gcm1 test =====")
	plain := []byte(strings.Repeat("Hello, world!", 4))
	keyBytes := []byte(strings.Repeat("0123", 11)) // 44 bytes

	m := new(SymMaster)
	m.Init("gcm1", keyBytes)

	enc, _ := m.EnBin(plain)
	dec, _ := m.DeBin(enc)
	fmt.Printf("b'%s' %d\n", string(dec), m.Processed())

	hugePlain := make([]byte, 100000000) // 100MB zero-filled
	r := bytes.NewReader(hugePlain)
	w := new(bytes.Buffer)
	m.EnFile(r, int64(len(hugePlain)), w)

	tBytes := w.Bytes()
	r = bytes.NewReader(tBytes)
	w = new(bytes.Buffer)
	m.DeFile(r, int64(len(tBytes)), w)

	fmt.Printf("%v %d\n", bytes.Equal(w.Bytes(), hugePlain), m.Processed())

	// ===== sym-gcmx1 test =====
	fmt.Println("\n===== sym-gcmx1 test =====")
	mx := new(SymMaster)
	mx.Init("gcmx1", keyBytes)

	encX, _ := mx.EnBin(plain)
	decX, _ := mx.DeBin(encX)
	fmt.Printf("b'%s' %d\n", string(decX), mx.Processed())

	r = bytes.NewReader(hugePlain)
	w = new(bytes.Buffer)
	mx.EnFile(r, int64(len(hugePlain)), w)

	tBytesX := w.Bytes()
	r = bytes.NewReader(tBytesX)
	w = new(bytes.Buffer)
	mx.DeFile(r, int64(len(tBytesX)), w)

	fmt.Printf("%v %d\n", bytes.Equal(w.Bytes(), hugePlain), mx.Processed())

	// ===== sym-vsizes test =====
	fmt.Println("\n===== sym-vsizes test =====")
	m1 := new(SymMaster)
	m1.Init("gcm1", keyBytes)
	m2 := new(SymMaster)
	m2.Init("gcmx1", keyBytes)

	encE, _ := m1.EnBin([]byte{})
	decE, _ := m1.DeBin(encE)
	fmt.Println(bytes.Equal(decE, []byte{}))

	r = bytes.NewReader([]byte{})
	w = new(bytes.Buffer)
	m2.EnFile(r, 0, w)
	tBytesV := w.Bytes()
	r = bytes.NewReader(tBytesV)
	w = new(bytes.Buffer)
	m2.DeFile(r, int64(len(tBytesV)), w)
	fmt.Println(bytes.Equal(w.Bytes(), []byte{}))

	r = bytes.NewReader([]byte{})
	w = new(bytes.Buffer)
	m2.EnFile(r, 0, w)
	tBytesV = w.Bytes()
	r = bytes.NewReader(tBytesV)
	w = new(bytes.Buffer)
	m2.DeFile(r, int64(len(tBytesV)), w)
	fmt.Println(bytes.Equal(w.Bytes(), []byte{}))

	plain4MB := make([]byte, 1048576*4)
	r = bytes.NewReader(plain4MB)
	w = new(bytes.Buffer)
	m2.EnFile(r, int64(len(plain4MB)), w)
	tBytesV = w.Bytes()
	r = bytes.NewReader(tBytesV)
	w = new(bytes.Buffer)
	m2.DeFile(r, int64(len(tBytesV)), w)
	fmt.Println(bytes.Equal(w.Bytes(), plain4MB))

	// ===== asym-rsa test =====
	fmt.Println("\n===== asym-rsa test =====")
	meRSA := new(AsymMaster)
	meRSA.Init("rsa1")
	meRSA.Genkey()

	youRSA := new(AsymMaster)
	youRSA.Init("rsa1")
	youRSA.Loadkey(b64d(pub0), b64d(pri0))

	encR, _ := meRSA.Encrypt(plain)
	decR, _ := meRSA.Decrypt(encR)
	fmt.Println(string(decR))

	signR, _ := meRSA.Sign(plain)
	fmt.Println(meRSA.Verify(plain, signR))

	decY, _ := youRSA.Decrypt(b64d(enc0))
	p(decY)
	fmt.Println(youRSA.Verify([]byte("0000"), b64d(sign0)))

	// ===== asym-ecc test =====
	fmt.Println("\n===== asym-ecc test =====")
	meECC := new(AsymMaster)
	meECC.Init("ecc1")
	meECC.Genkey()

	youECC := new(AsymMaster)
	youECC.Init("ecc1")
	youECC.Loadkey(b64d(pub1), b64d(pri1))

	encE2, _ := meECC.Encrypt(plain)
	decE2, _ := meECC.Decrypt(encE2)
	fmt.Println(string(decE2))

	signE2, _ := meECC.Sign(plain)
	fmt.Println(meECC.Verify(plain, signE2))

	decY2, _ := youECC.Decrypt(b64d(enc1))
	p(decY2)
	fmt.Println(youECC.Verify([]byte("0000"), b64d(sign1)))
}
