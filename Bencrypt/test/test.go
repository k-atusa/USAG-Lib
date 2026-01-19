// go mod init example.com
// go mod tidy
// go run test.go

package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"

	Bencrypt "github.com/k-atusa/USAG-Lib/Bencrypt"
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

func main() {
	// ===== basic test =====
	fmt.Println("\n===== basic test =====")
	print(Bencrypt.Random(16))
	print(Bencrypt.Sha3256([]byte{}))
	print(Bencrypt.Sha3512([]byte{}))
	print(Bencrypt.Pbkdf2([]byte("0000"), []byte("0000000000000000"), 0, 0)) // 0 uses default iter/size

	t := Bencrypt.Argon2Hash([]byte("0000"), []byte("0000000000000000"))
	fmt.Println(t)
	fmt.Println(Bencrypt.Argon2Verify(t, []byte("0000")))

	k, _ := Bencrypt.Genkey([]byte("0000000000000000"), "test", 16)
	print(k)

	// ===== aes test =====
	fmt.Println("\n===== aes test =====")
	plain := []byte(strings.Repeat("Hello, world!", 4))
	keyBytes := []byte(strings.Repeat("0123", 11))
	var key [44]byte
	copy(key[:], keyBytes)

	m := Bencrypt.AES1{}
	m.Init() // Ensure processed is 0

	// EnAESGCM
	enc, err := m.EnAESGCM(key, plain)
	if err != nil {
		panic(err)
	}
	print(enc)
	fmt.Println(m.Processed())

	// DeAESGCM
	dec, err := m.DeAESGCM(key, enc)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(dec))
	fmt.Println(m.Processed())

	// EnAESGCMx (Streaming)
	plainLarge := make([]byte, 100000000) // 100MB
	r := bytes.NewReader(plainLarge)
	w := new(bytes.Buffer)
	err = m.EnAESGCMx(key, r, len(plainLarge), w, 0) // 0 for default chunk size
	if err != nil {
		panic(err)
	}
	tBytes := w.Bytes()
	print(tBytes[0:16])
	fmt.Println(m.Processed())

	// DeAESGCMx (Streaming)
	r = bytes.NewReader(tBytes)
	w = new(bytes.Buffer)
	err = m.DeAESGCMx(key, r, len(tBytes), w, 0)
	if err != nil {
		panic(err)
	}
	fmt.Println(m.Processed())
	fmt.Println(bytes.Equal(w.Bytes(), plainLarge))

	// Test various sizes
	// Empty EnAESGCM
	tBytes, _ = m.EnAESGCM(key, []byte{})
	dec, _ = m.DeAESGCM(key, tBytes)
	fmt.Println(bytes.Equal(dec, []byte{}))

	// Empty Streaming
	r = bytes.NewReader([]byte{})
	w = new(bytes.Buffer)
	m.EnAESGCMx(key, r, 0, w, 0)
	tBytes = w.Bytes()
	r = bytes.NewReader(tBytes)
	w = new(bytes.Buffer)
	m.DeAESGCMx(key, r, len(tBytes), w, 0)
	fmt.Println(bytes.Equal(w.Bytes(), []byte{}))

	// 4MiB Streaming
	plain4MB := make([]byte, 1048576*4)
	r = bytes.NewReader(plain4MB)
	w = new(bytes.Buffer)
	m.EnAESGCMx(key, r, len(plain4MB), w, 0)
	tBytes = w.Bytes()
	r = bytes.NewReader(tBytes)
	w = new(bytes.Buffer)
	m.DeAESGCMx(key, r, len(tBytes), w, 0)
	fmt.Println(bytes.Equal(w.Bytes(), plain4MB))

	// ===== rsa test =====
	fmt.Println("\n===== rsa test =====")
	you := Bencrypt.RSA1{}
	err = you.Loadkey(b64d(pub0), b64d(pri0))
	if err != nil {
		panic(err)
	}

	enc, err = you.Encrypt([]byte(strings.Repeat("Hello, world!", 4)))
	if err != nil {
		panic(err)
	}
	dec, err = you.Decrypt(enc)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(dec))

	me := Bencrypt.RSA1{}
	_, _, err = me.Genkey(0) // 0 for default bits
	if err != nil {
		panic(err)
	}

	enc, err = me.Sign([]byte(strings.Repeat("Hello, world!", 4)))
	if err != nil {
		panic(err)
	}
	fmt.Println(me.Verify([]byte(strings.Repeat("Hello, world!", 4)), enc))

	// Compatibility Check (Decrypt enc0)
	dec0, err := you.Decrypt(b64d(enc0))
	if err != nil {
		fmt.Println("Decrypt Error:", err)
	} else {
		print(dec0)
	}

	// Compatibility Check (Verify sign0)
	fmt.Println(you.Verify([]byte("0000"), b64d(sign0)))

	// ===== ecc test =====
	fmt.Println("\n===== ecc test =====")
	youEcc := Bencrypt.ECC1{}
	err = youEcc.Loadkey(b64d(pub1), b64d(pri1))
	if err != nil {
		panic(err)
	}

	meEcc := Bencrypt.ECC1{}
	_, _, err = meEcc.Genkey()
	if err != nil {
		panic(err)
	}

	// Encrypt
	enc, err = meEcc.Encrypt([]byte(strings.Repeat("Hello, world!", 4)), b64d(pub1))
	if err != nil {
		panic(err)
	}
	dec, err = youEcc.Decrypt(enc)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(dec))

	// Sign
	enc, err = meEcc.Sign([]byte(strings.Repeat("Hello, world!", 4)))
	if err != nil {
		panic(err)
	}
	fmt.Println(meEcc.Verify([]byte(strings.Repeat("Hello, world!", 4)), enc))

	// Compatibility Check (Decrypt enc1)
	dec1, err := youEcc.Decrypt(b64d(enc1))
	if err != nil {
		fmt.Println("Decrypt Error:", err)
	} else {
		print(dec1)
	}

	// Compatibility Check (Verify sign1)
	fmt.Println(youEcc.Verify([]byte("0000"), b64d(sign1)))
}
