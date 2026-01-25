// test793c : USAG-Lib bencrypt

package Bencrypt

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"

	"github.com/cloudflare/circl/dh/x448"
	"github.com/cloudflare/circl/sign/ed448"
)

type aesResult struct {
	data []byte
	err  error
}

func mkiv(g []byte, c uint64) []byte {
	// Create a copy to avoid mutating the original slice if it's reused
	iv := make([]byte, len(g))
	copy(iv, g)

	// Convert counter to 8 bytes Little Endian
	counterBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(counterBytes, c)

	// XOR bytes 4~11
	for i := 0; i < 8; i++ {
		iv[4+i] ^= counterBytes[i]
	}
	return iv
}

// ========== Basic Functions ==========
func Random(size int) []byte {
	b := make([]byte, size)
	_, err := rand.Read(b)
	if err != nil {
		panic(err) // Cryptographic RNG failure is usually fatal
	}
	return b
}

func Sha3256(data []byte) []byte {
	hash := sha3.Sum256(data)
	return hash[:]
}

func Sha3512(data []byte) []byte {
	hash := sha3.Sum512(data)
	return hash[:]
}

// default iter=1000000, outsize=64
func Pbkdf2(pw []byte, salt []byte, iter int, outsize int) []byte {
	if iter <= 0 {
		iter = 1000000
	}
	if outsize <= 0 {
		outsize = 64
	}
	return pbkdf2.Key(pw, salt, iter, outsize, sha512.New)
}

// fixxed parameters: Time=3, Mem=262144(256MB), Parallel=4, HashLen=32
func Argon2Hash(pw []byte, salt []byte) string {
	if salt == nil {
		salt = Random(16)
	}
	const (
		time    = 3
		memory  = 262144
		threads = 4
		keyLen  = 32
	)

	hash := argon2.IDKey(pw, salt, time, memory, threads, keyLen)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt) // base64 with no padding
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", memory, time, threads, b64Salt, b64Hash) // format: $argon2id$v=19$m=262144,t=3,p=4$saltB64$hashB64
}

func Argon2Verify(hashed string, pw []byte) bool {
	// Parse parameters
	parts := strings.Split(hashed, "$")
	if len(parts) != 6 {
		return false
	}
	if parts[1] != "argon2id" {
		return false
	}
	var memory, time uint32
	var threads uint8
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads)
	if err != nil {
		return false
	}

	// Decode Salt and Hash
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	originalHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}

	// Re-hash, const-time compare
	newHash := argon2.IDKey(pw, salt, time, memory, threads, uint32(len(originalHash)))
	return hmac.Equal(originalHash, newHash)
}

// make key using HMAC-SHA3-512
func Genkey(data []byte, lbl string, size int) ([]byte, error) {
	h := hmac.New(func() hash.Hash { return sha3.New512() }, data)
	h.Write([]byte(lbl))
	key := h.Sum(nil)
	if size > len(key) {
		return nil, errors.New("key size too large")
	}
	return key[:size], nil
}

// ========== Encrypting Functions ==========
type AES1 struct {
	processed int64
}

func (a *AES1) Init() { a.processed = 0 }

func (a *AES1) Processed() int64 { return atomic.LoadInt64(&a.processed) }

// AES-GCM encryption, 44B key (12B IV + 32B AES Key)
func (a *AES1) EnAESGCM(key [44]byte, data []byte) ([]byte, error) {
	// basic setup
	a.processed = 0
	iv := key[:12]
	aeskey := key[12:]

	// make AES cipher
	block, e0 := aes.NewCipher(aeskey)
	if e0 != nil {
		return nil, e0
	}
	aesgcm, e1 := cipher.NewGCM(block)
	if e1 != nil {
		return nil, e1
	}

	// encrypt
	enc := aesgcm.Seal(nil, iv, data, nil)
	a.processed = int64(len(data))
	return enc, nil // format: [encdata][tag 16B]
}

// AES-GCM decryption, 44B key (12B IV + 32B AES Key)
func (a *AES1) DeAESGCM(key [44]byte, data []byte) ([]byte, error) {
	// basic setup
	a.processed = 0
	if len(data) < 16 {
		return nil, errors.New("data too short")
	}
	iv := key[:12]
	aeskey := key[12:]

	// make AES cipher
	block, e0 := aes.NewCipher(aeskey)
	if e0 != nil {
		return nil, e0
	}
	aesgcm, e1 := cipher.NewGCM(block)
	if e1 != nil {
		return nil, e1
	}

	// decrypt
	plain, e2 := aesgcm.Open(nil, iv, data, nil)
	if e2 != nil {
		return nil, e2
	}
	a.processed = int64(len(data))
	return plain, nil
}

// AES-GCM extended, 44B key (12B IV + 32B AES Key), default chunkSize=1048576
func (a *AES1) EnAESGCMx(key [44]byte, src io.Reader, size int64, dst io.Writer, chunkSize int) error {
	// basic setup
	a.processed = 0
	if chunkSize <= 0 {
		chunkSize = 1048576 // 1MiB
	}
	globalIV := key[:12]
	globalKey := key[12:]
	var memPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, chunkSize+16)
		},
	}
	thrN := runtime.NumCPU()
	if thrN <= 0 {
		thrN = 1
	}

	// make AES cipher
	block, e0 := aes.NewCipher(globalKey)
	if e0 != nil {
		return e0
	}
	aesgcm, e1 := cipher.NewGCM(block)
	if e1 != nil {
		return e1
	}

	// task setup
	var rErr error = nil
	wErr := make(chan error, 1)
	writeQue := make(chan chan aesResult, thrN*2)
	var wg sync.WaitGroup

	// Start writer goroutine
	wg.Add(1)
	go func() {
		defer func() {
			if e := recover(); e != nil {
				wErr <- e.(error) // panic to error
			}
			close(wErr)
			wg.Done()
		}()
		for ch := range writeQue {
			res := <-ch         // get result
			if res.err != nil { // quit if error occurs
				wErr <- res.err
				return
			}
			_, e := dst.Write(res.data) // write data
			if e != nil {
				wErr <- e
				return
			}
			atomic.AddInt64(&a.processed, int64(len(res.data)-16))
			if cap(res.data) >= chunkSize+16 { // return buffer
				memPool.Put(res.data[:0])
			}
		}
	}()

	// Read, submit task
	var counter uint64 = 0
	remaining := size
	loopCtrl := true
	for loopCtrl {
		// get buffer
		toRead := min(remaining, int64(chunkSize))
		buf := memPool.Get().([]byte)
		if cap(buf) < int(toRead) {
			buf = make([]byte, toRead)
		}
		buf = buf[:toRead]

		// read buffer
		_, err := io.ReadFull(src, buf)
		if err != nil {
			if err == io.EOF {
				loopCtrl = false
			} else {
				rErr = err
				break
			}
		}
		remaining -= toRead

		// make iv, submit task
		currentIV := mkiv(globalIV, counter)
		counter++
		future := make(chan aesResult, 1)
		select {
		case writeQue <- future:
		case err := <-wErr:
			return err
		}

		// encryption goroutine
		go func(m cipher.AEAD, key []byte, iv []byte, data []byte, outCh chan aesResult) {
			var r aesResult
			defer func() {
				if e := recover(); e != nil {
					r.err = e.(error) // panic to error
				}
				outCh <- r
				close(outCh)
			}()
			r.data = aesgcm.Seal(data[:0], iv, data, nil)
		}(aesgcm, globalKey, currentIV, buf, future)
		if remaining <= 0 {
			loopCtrl = false
		}
	}

	// wait for writer, return
	close(writeQue)
	wg.Wait()
	select {
	case err := <-wErr:
		return err
	default:
		return rErr
	}
}

// AES-GCM extended, 44B key (12B IV + 32B AES Key), default chunkSize=1048576
func (a *AES1) DeAESGCMx(key [44]byte, src io.Reader, size int64, dst io.Writer, chunkSize int) error {
	// basic setup
	a.processed = 0
	if chunkSize <= 0 {
		chunkSize = 1048576 // 1MiB
	}
	globalIV := key[:12]
	globalKey := key[12:]
	var memPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, chunkSize+16)
		},
	}
	thrN := runtime.NumCPU()
	if thrN <= 0 {
		thrN = 1
	}

	// make AES cipher
	block, e0 := aes.NewCipher(globalKey)
	if e0 != nil {
		return e0
	}
	aesgcm, e1 := cipher.NewGCM(block)
	if e1 != nil {
		return e1
	}

	// task setup
	var rErr error = nil
	wErr := make(chan error, 1)
	writeQue := make(chan chan aesResult, thrN*2)
	var wg sync.WaitGroup

	// Start writer goroutine
	wg.Add(1)
	go func() {
		defer func() {
			if e := recover(); e != nil {
				wErr <- e.(error) // panic to error
			}
			close(wErr)
			wg.Done()
		}()
		for ch := range writeQue {
			res := <-ch         // get result
			if res.err != nil { // quit if error occurs
				wErr <- res.err
				return
			}
			_, e := dst.Write(res.data) // write data
			if e != nil {
				wErr <- e
				return
			}
			atomic.AddInt64(&a.processed, int64(len(res.data)+16))
			if cap(res.data) >= chunkSize+16 { // return buffer
				memPool.Put(res.data[:0])
			}
		}
	}()

	// Read, submit task
	var counter uint64 = 0
	remaining := size
	for remaining >= 16 {
		// get buffer
		toRead := min(int64(chunkSize+16), remaining)
		buf := memPool.Get().([]byte)
		if cap(buf) < int(toRead) {
			buf = make([]byte, toRead)
		}
		buf = buf[:toRead]

		// read buffer
		_, err := io.ReadFull(src, buf)
		if err != nil {
			if err == io.EOF {
				remaining = 0
			} else {
				rErr = err
				break
			}
		}
		remaining -= toRead

		// make iv, submit task
		currentIV := mkiv(globalIV, counter)
		counter++
		future := make(chan aesResult, 1)
		select {
		case writeQue <- future:
		case err := <-wErr:
			return err
		}

		// encryption goroutine
		go func(m cipher.AEAD, key []byte, iv []byte, data []byte, outCh chan aesResult) {
			var r aesResult
			defer func() {
				if e := recover(); e != nil {
					r.err = e.(error) // panic to error
				}
				outCh <- r
				close(outCh)
			}()
			r.data, r.err = aesgcm.Open(data[:0], iv, data, nil)
		}(aesgcm, globalKey, currentIV, buf, future)
	}

	// wait for writer, return
	close(writeQue)
	wg.Wait()
	select {
	case err := <-wErr:
		return err
	default:
		return rErr
	}
}

// ========== Signing Functions ==========
type RSA1 struct {
	Private *rsa.PrivateKey
	Public  *rsa.PublicKey
}

// DER(PKIX, PKCS8) format, returns (public, private, error)
func (r *RSA1) Genkey(bits int) ([]byte, []byte, error) {
	if bits <= 0 {
		bits = 2048 // Default bits: 2048
	}
	// 1. Generate Key
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	r.Private = key
	r.Public = &key.PublicKey

	// 2. Marshal Public Key (PKIX / DER)
	pubBytes, err := x509.MarshalPKIXPublicKey(r.Public)
	if err != nil {
		return nil, nil, err
	}

	// 3. Marshal Private Key (PKCS8 / DER)
	privBytes, err := x509.MarshalPKCS8PrivateKey(r.Private)
	if err != nil {
		return nil, nil, err
	}
	return pubBytes, privBytes, nil
}

// Load keys from DER(PKIX, PKCS8) format bytes. Pass nil to skip.
func (r *RSA1) Loadkey(public []byte, private []byte) error {
	if public != nil {
		pubInterface, err := x509.ParsePKIXPublicKey(public)
		if err != nil {
			return err
		}
		pubKey, ok := pubInterface.(*rsa.PublicKey)
		if !ok {
			return errors.New("not an RSA public key")
		}
		r.Public = pubKey
	}

	if private != nil {
		privInterface, err := x509.ParsePKCS8PrivateKey(private)
		if err != nil {
			return err
		}
		privKey, ok := privInterface.(*rsa.PrivateKey)
		if !ok {
			return errors.New("not an RSA private key")
		}
		r.Private = privKey
	}
	return nil
}

// OAEP-SHA-512
func (r *RSA1) Encrypt(data []byte) ([]byte, error) {
	hash := sha512.New()
	return rsa.EncryptOAEP(hash, rand.Reader, r.Public, data, nil)
}

// OAEP-SHA-512
func (r *RSA1) Decrypt(data []byte) ([]byte, error) {
	hash := sha512.New()
	return rsa.DecryptOAEP(hash, rand.Reader, r.Private, data, nil)
}

// PKCS1 v1.5 + SHA256
func (r *RSA1) Sign(data []byte) ([]byte, error) {
	hashed := sha256.Sum256(data)
	return rsa.SignPKCS1v15(rand.Reader, r.Private, crypto.SHA256, hashed[:])
}

// PKCS1 v1.5 + SHA256, returns true if valid
func (r *RSA1) Verify(data []byte, signature []byte) bool {
	hashed := sha256.Sum256(data)
	err := rsa.VerifyPKCS1v15(r.Public, crypto.SHA256, hashed[:], signature)
	return err == nil
}

type ECC1 struct {
	// X448 Keys (Encryption)
	PrivX *x448.Key
	PubX  *x448.Key

	// Ed448 Keys (Signing)
	PrivEd ed448.PrivateKey
	PubEd  ed448.PublicKey

	// Format: [1B PubLen][TempPub][EncData]
	em AES1
}

// Generates keys: [X448 56B][Ed448 57B], (public bytes, private bytes, error)
func (e *ECC1) Genkey() ([]byte, []byte, error) {
	// 1. Generate X448 (56 bytes)
	var xPub, xPriv x448.Key
	// random bytes for private key
	if _, err := io.ReadFull(rand.Reader, xPriv[:]); err != nil {
		return nil, nil, err
	}
	x448.KeyGen(&xPub, &xPriv)
	e.PrivX = &xPriv
	e.PubX = &xPub

	// 2. Generate Ed448 (57 bytes public, 57 bytes private seed)
	edPub, edPriv, err := ed448.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	e.PubEd = edPub
	e.PrivEd = edPriv

	// 3. Serialize Public: 56 + 57 = 113
	pubBytes := make([]byte, 113)
	copy(pubBytes[:56], e.PubX[:])
	copy(pubBytes[56:], e.PubEd)

	// 4. Serialize Private: 56 + 57 = 113
	privBytes := make([]byte, 113)
	copy(privBytes[:56], e.PrivX[:])
	copy(privBytes[56:], e.PrivEd.Seed()) // Use Seed() to get the raw 57B private scalar
	return pubBytes, privBytes, nil
}

// Load keys. Public must be 113B, Private must be 113B.
func (e *ECC1) Loadkey(public []byte, private []byte) error {
	if public != nil {
		if len(public) != 113 {
			return errors.New("invalid public key length (must be 113 bytes for Curve448)")
		}
		// Load X448 Public
		e.PubX = new(x448.Key)
		copy(e.PubX[:], public[:56])

		// Load Ed448 Public
		e.PubEd = make(ed448.PublicKey, ed448.PublicKeySize)
		copy(e.PubEd, public[56:])
	}

	if private != nil {
		if len(private) != 113 {
			return errors.New("invalid private key length (must be 113 bytes for Curve448)")
		}
		// Load X448 Private
		e.PrivX = new(x448.Key)
		copy(e.PrivX[:], private[:56])

		// Load Ed448 Private (Re-derive full key from seed)
		e.PrivEd = ed448.NewKeyFromSeed(private[56:])
	}
	return nil
}

// Encrypt data using public key (Hybrid: ECDH + AES-GCM)
func (e *ECC1) Encrypt(data []byte) ([]byte, error) {
	// 1. Generate temp ephemeral key
	var tempPub, tempPriv x448.Key
	if _, err := io.ReadFull(rand.Reader, tempPriv[:]); err != nil {
		return nil, err
	}
	x448.KeyGen(&tempPub, &tempPriv)

	// 2. Get shared secret (ECDH)
	var shared x448.Key
	ok := x448.Shared(&shared, &tempPriv, e.PubX)
	if !ok {
		return nil, errors.New("ECDH key exchange failed (bad public key)")
	}

	// 3. Derive Key & Encrypt with AES-GCM
	gcmKey, err := Genkey(shared[:], "KEYGEN_ECC1_ENCRYPT", 44)
	if err != nil {
		return nil, err
	}
	var keyArr [44]byte
	copy(keyArr[:], gcmKey)
	enc, err := e.em.EnAESGCM(keyArr, data)
	if err != nil {
		return nil, err
	}

	// Join to make [1B Len][TempPub 56B][Enc]
	out := make([]byte, 1+56+len(enc))
	out[0] = 56 // X448 pub key length
	copy(out[1:], tempPub[:])
	copy(out[1+56:], enc)
	return out, nil
}

// Decrypt data using private key (Hybrid: ECDH + AES-GCM)
func (e *ECC1) Decrypt(data []byte) ([]byte, error) {
	// 1. Parse data
	if len(data) < 57 {
		return nil, errors.New("data too short")
	}
	keylen := int(data[0])
	if keylen != 56 {
		return nil, errors.New("unsupported public key length")
	}
	var tempPub x448.Key
	copy(tempPub[:], data[1:1+keylen])
	enc := data[1+keylen:]

	// 2. Get shared secret (ECDH)
	var shared x448.Key
	ok := x448.Shared(&shared, e.PrivX, &tempPub)
	if !ok {
		return nil, errors.New("ECDH key exchange failed")
	}

	// 3. Decrypt with AES-GCM
	gcmKey, err := Genkey(shared[:], "KEYGEN_ECC1_ENCRYPT", 44)
	if err != nil {
		return nil, err
	}
	var keyArr [44]byte
	copy(keyArr[:], gcmKey)
	return e.em.DeAESGCM(keyArr, enc)
}

// Ed448 Sign (empty context is default)
func (e *ECC1) Sign(data []byte) ([]byte, error) {
	if e.PrivEd == nil {
		return nil, errors.New("private key not loaded")
	}
	// Python cryptography signs with empty context by default for Ed448
	return ed448.Sign(e.PrivEd, data, ""), nil
}

// Ed448 Verify
func (e *ECC1) Verify(data []byte, signature []byte) bool {
	if e.PubEd == nil {
		return false
	}
	return ed448.Verify(e.PubEd, data, signature, "")
}
