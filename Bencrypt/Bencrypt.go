// test793c : USAG-Lib bencrypt

package Bencrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"runtime"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
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
func Pbkdf2(pw []byte, salt []byte, iter int, outsize int) ([]byte, error) {
	if iter <= 0 {
		iter = 1000000
	}
	if outsize <= 0 {
		outsize = 64
	}
	return pbkdf2.Key(sha512.New, string(pw), salt, iter, outsize)
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
	Processed int
}

func (a *AES1) Init() { a.Processed = 0 }

func (a *AES1) inlineEnc(key []byte, iv []byte, data []byte) []byte {
	block, e0 := aes.NewCipher(key)
	aesgcm, e1 := cipher.NewGCM(block)
	if e0 != nil || e1 != nil {
		panic(e0.Error() + e1.Error()) // AES fail should not happen
	}
	return aesgcm.Seal(data[:0], iv, data, nil)
}

func (a *AES1) inlineDec(key []byte, iv []byte, data []byte) []byte {
	block, e0 := aes.NewCipher(key)
	aesgcm, e1 := cipher.NewGCM(block)
	plain, e2 := aesgcm.Open(data[:0], iv, data, nil)
	if e0 != nil || e1 != nil || e2 != nil {
		panic(e0.Error() + e1.Error() + e2.Error()) // AES fail should not happen
	}
	return plain
}

// AES-GCM encryption, 44B key (12B IV + 32B AES Key)
func (a *AES1) EnAESGCM(key [44]byte, data []byte) []byte {
	a.Processed = 0
	iv := key[:12]
	aeskey := key[12:]
	d := make([]byte, len(data), len(data)+16)
	copy(d, data)
	enc := a.inlineEnc(aeskey, iv, d)
	a.Processed = len(data)
	return enc // format: [encdata][tag 16B]
}

// AES-GCM decryption, 44B key (12B IV + 32B AES Key)
func (a *AES1) DeAESGCM(key [44]byte, data []byte) []byte {
	a.Processed = 0
	if len(data) < 16 {
		return nil
	}
	iv := key[:12]
	aeskey := key[12:]
	d := make([]byte, len(data))
	copy(d, data)
	plain := a.inlineDec(aeskey, iv, d)
	a.Processed = len(data)
	return plain
}

// AES-GCM extended, 44B key (12B IV + 32B AES Key), default chunkSize=1048576
func (a *AES1) EnAESGCMx(key [44]byte, src io.Reader, size int, dst io.Writer, chunkSize int) error {
	// basic setup
	a.Processed = 0
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
			a.Processed += (len(res.data) - 16)
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
		toRead := min(remaining, chunkSize)
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
		go func(key []byte, iv []byte, data []byte, outCh chan aesResult) {
			var r aesResult
			defer func() {
				if e := recover(); e != nil {
					r.err = e.(error) // panic to error
				}
				outCh <- r
				close(outCh)
			}()
			r.data = a.inlineEnc(key, iv, data)
		}(globalKey, currentIV, buf, future)
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
func (a *AES1) DeAESGCMx(key [44]byte, src io.Reader, size int, dst io.Writer, chunkSize int) error {
	// basic setup
	a.Processed = 0
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
			a.Processed += (len(res.data) + 16)
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
		toRead := min(chunkSize+16, remaining)
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
		go func(key []byte, iv []byte, data []byte, outCh chan aesResult) {
			var r aesResult
			defer func() {
				if e := recover(); e != nil {
					r.err = e.(error) // panic to error
				}
				outCh <- r
				close(outCh)
			}()
			r.data = a.inlineDec(key, iv, data)
		}(globalKey, currentIV, buf, future)
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
