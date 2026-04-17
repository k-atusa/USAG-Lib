// test794bc : USAG-Lib opsec

package Opsec

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"

	Bencrypt "github.com/k-atusa/USAG-Lib/Bencrypt"
)

// ========== Helper Functions ==========
func Crc32(data []byte) string {
	checksum := crc32.ChecksumIEEE(data)
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, checksum)
	return hex.EncodeToString(buf)
}

func EncodeInt(data uint64, size int) []byte {
	buf := make([]byte, size)
	switch size {
	case 1:
		buf[0] = byte(data)
	case 2:
		binary.LittleEndian.PutUint16(buf, uint16(data))
	case 4:
		binary.LittleEndian.PutUint32(buf, uint32(data))
	case 8:
		binary.LittleEndian.PutUint64(buf, data)
	}
	return buf
}

func DecodeInt(data []byte) uint64 {
	l := len(data)
	switch l {
	case 1:
		return uint64(data[0])
	case 2:
		return uint64(binary.LittleEndian.Uint16(data))
	case 4:
		return uint64(binary.LittleEndian.Uint32(data))
	case 8:
		return binary.LittleEndian.Uint64(data)
	default:
		return 0
	}
}

// Config Encoding, keysize max 127, datasize max 65535
func EncodeCfg(data map[string][]byte) ([]byte, error) {
	var buf bytes.Buffer
	for key, val := range data {
		keyBytes := []byte(key)
		keyLen := len(keyBytes)
		dataLen := len(val)
		if keyLen > 127 {
			return nil, errors.New("key length too long")
		}
		if dataLen > 65535 {
			return nil, errors.New("data size too big")
		}

		if dataLen > 255 {
			buf.WriteByte(byte(keyLen + 128))
			buf.Write(keyBytes)
			buf.Write(EncodeInt(uint64(dataLen), 2))
		} else {
			buf.WriteByte(byte(keyLen))
			buf.Write(keyBytes)
			buf.WriteByte(byte(dataLen))
		}
		buf.Write(val)
	}
	return buf.Bytes(), nil
}

// Config Decoding, [keyLen 1B][key][dataLen 1B/2B][data]
func DecodeCfg(data []byte) map[string][]byte {
	result := make(map[string][]byte)
	totalLen := len(data)
	offset := 0
	for offset < totalLen {
		// Get Key
		keyLen := int(data[offset])
		offset++
		isLongData := false
		if keyLen > 127 {
			keyLen -= 128
			isLongData = true
		}
		key := string(data[offset : offset+keyLen])
		offset += keyLen

		// Get Data
		var dataLen int
		if isLongData {
			dataLen = int(DecodeInt(data[offset : offset+2]))
			offset += 2
		} else {
			dataLen = int(data[offset])
			offset++
		}
		result[key] = data[offset : offset+dataLen]
		offset += dataLen
	}
	return result
}

// Opsec header handler
type Opsec struct {
	// Outer Layer
	Msg         string // non-secured message
	MsgInfo     []byte // additional info (for RSA-mode)
	headAlgo    string // header algorithm
	salt        []byte // salt
	pwHash      []byte // pw hash
	encHeadData []byte // encrypted header data

	// Inner Layer
	Smsg     string // secured message
	SmsgInfo []byte // private additional info (timestamp, ID, etc.)
	sign     []byte // signature

	BodyAlgo string // body algorithm
	BodyKey  []byte // body key
	BodySize int64  // full body size, flag for bodyKey generation
	BodyInfo []byte // additional info for body (packing info, etc.)

	SaltLen int
}

// reset after reading BodyKey
func (o *Opsec) Reset() {
	o.Msg = ""
	o.MsgInfo = []byte{}
	o.headAlgo = ""
	o.salt = []byte{}
	o.pwHash = []byte{}
	o.encHeadData = []byte{}

	o.Smsg = ""
	o.SmsgInfo = []byte{}
	o.sign = []byte{}

	o.BodyAlgo = ""
	o.BodyKey = []byte{}
	o.BodySize = -1
	o.BodyInfo = []byte{}

	o.SaltLen = 32
}

// Read opsec header from stream, set cut to 0 to read all
func (o *Opsec) Read(r io.Reader, cut int) ([]byte, error) {
	c := 0
	buf4 := make([]byte, 4)
	buf2 := make([]byte, 2)
	buf124 := make([]byte, 124)
	for {
		_, err := io.ReadFull(r, buf4)
		if err != nil { // EOF or Error
			return nil, nil
		}
		c += 4

		if string(buf4) == "YAS2" { // magic number
			_, err := io.ReadFull(r, buf2)
			if err != nil {
				return nil, err
			}
			size := int(DecodeInt(buf2))
			if size == 65535 {
				_, err := io.ReadFull(r, buf2)
				if err != nil {
					return nil, err
				}
				size += int(DecodeInt(buf2))
			}

			// Read payload
			payload := make([]byte, size)
			_, err = io.ReadFull(r, payload)
			if err != nil {
				return nil, err
			}
			return payload, nil

		} else { // skip
			_, err := io.ReadFull(r, buf124)
			if err != nil {
				return nil, nil
			}
			c += 124
		}
		if cut > 0 && c > cut {
			return nil, nil
		}
	}
}

// Write opsec header to stream
func (o *Opsec) Write(w io.Writer, head []byte) error {
	if _, err := w.Write([]byte("YAS2")); err != nil {
		return err
	}
	size := len(head)
	if size < 65535 {
		if _, err := w.Write(EncodeInt(uint64(size), 2)); err != nil {
			return err
		}
	} else if size <= 65535*2 {
		if _, err := w.Write(EncodeInt(65535, 2)); err != nil {
			return err
		}
		if _, err := w.Write(EncodeInt(uint64(size-65535), 2)); err != nil {
			return err
		}
	} else {
		return errors.New("data size too big")
	}
	if _, err := w.Write(head); err != nil {
		return err
	}
	return nil
}

func (o *Opsec) wrapEncHead() ([]byte, error) {
	cfg := make(map[string][]byte)
	if o.Smsg != "" {
		cfg["smsg"] = []byte(o.Smsg)
	}
	if len(o.SmsgInfo) > 0 {
		cfg["sinf"] = o.SmsgInfo
	}
	if len(o.sign) > 0 {
		cfg["sgn"] = o.sign
	}
	if o.BodyAlgo != "" {
		cfg["bal"] = []byte(o.BodyAlgo)
	}
	if len(o.BodyKey) > 0 {
		cfg["bkey"] = o.BodyKey
	}
	if o.BodySize >= 0 {
		var szBytes []byte
		if o.BodySize < 65536 {
			szBytes = EncodeInt(uint64(o.BodySize), 2)
		} else if o.BodySize < 4294967296 {
			szBytes = EncodeInt(uint64(o.BodySize), 4)
		} else {
			szBytes = EncodeInt(uint64(o.BodySize), 8)
		}
		cfg["bsz"] = szBytes
	}
	if len(o.BodyInfo) > 0 {
		cfg["binf"] = o.BodyInfo
	}
	return EncodeCfg(cfg)
}

func (o *Opsec) unwrapEncHead(data []byte) {
	cfg := DecodeCfg(data)
	if v, ok := cfg["smsg"]; ok {
		o.Smsg = string(v)
	}
	if v, ok := cfg["sinf"]; ok {
		o.SmsgInfo = v
	}
	if v, ok := cfg["sgn"]; ok {
		o.sign = v
	}
	if v, ok := cfg["bal"]; ok {
		o.BodyAlgo = string(v)
	}
	if v, ok := cfg["bkey"]; ok {
		o.BodyKey = v
	}
	if v, ok := cfg["bsz"]; ok {
		o.BodySize = int64(DecodeInt(v))
	}
	if v, ok := cfg["binf"]; ok {
		o.BodyInfo = v
	}
}

// Encrypt with password
func (o *Opsec) Encpw(method string, pw []byte, kf []byte) ([]byte, error) {
	// generate random parameters
	if o.SaltLen <= 0 {
		o.SaltLen = 32
	}
	o.headAlgo = method
	o.salt = Bencrypt.Random(o.SaltLen)
	if o.BodySize >= 0 {
		o.BodyKey = Bencrypt.Random(44)
	}

	// Combine pw + kf
	combinedPw := make([]byte, 0, len(pw)+len(kf))
	combinedPw = append(combinedPw, pw...)
	combinedPw = append(combinedPw, kf...)

	// KDF via HashMaster
	hm := new(Bencrypt.HashMaster)
	if err := hm.Init(method, 32, 44); err != nil {
		return nil, err
	}
	pwHash, hkey, err := hm.KDF(combinedPw, o.salt)
	if err != nil {
		return nil, err
	}
	o.pwHash = pwHash

	// Encrypt header
	headData, err := o.wrapEncHead()
	if err != nil {
		return nil, err
	}
	sm := new(Bencrypt.SymMaster)
	if err := sm.Init("gcm1", hkey); err != nil {
		return nil, err
	}
	o.encHeadData, err = sm.EnBin(headData)
	if err != nil {
		return nil, err
	}

	// Wrap outer header
	cfg := make(map[string][]byte)
	if o.Msg != "" {
		cfg["msg"] = []byte(o.Msg)
	}
	if len(o.MsgInfo) > 0 {
		cfg["minf"] = o.MsgInfo
	}
	cfg["hal"] = []byte(o.headAlgo)
	cfg["salt"] = o.salt
	cfg["pwh"] = o.pwHash
	cfg["ehd"] = o.encHeadData
	return EncodeCfg(cfg)
}

// Encrypt with public key, sign if private key is not nil
func (o *Opsec) Encpub(method string, peerPub []byte, myPri []byte) ([]byte, error) {
	o.headAlgo = method
	if o.BodySize >= 0 {
		o.BodyKey = Bencrypt.Random(44)
	}

	// Sign if private key is provided
	if myPri != nil {
		amSign := new(Bencrypt.AsymMaster)
		if err := amSign.Init(method); err != nil {
			return nil, err
		}
		if err := amSign.Loadkey(nil, myPri); err != nil {
			return nil, err
		}

		signTgt := make([]byte, 0)
		signTgt = append(signTgt, []byte(method)...)
		signTgt = append(signTgt, peerPub...)
		signTgt = append(signTgt, []byte(o.Smsg)...)
		signTgt = append(signTgt, o.SmsgInfo...)

		var err error
		o.sign, err = amSign.Sign(signTgt)
		if err != nil {
			return nil, err
		}
	}

	// Encrypt header
	amEncrypt := new(Bencrypt.AsymMaster)
	if err := amEncrypt.Init(method); err != nil {
		return nil, err
	}
	if err := amEncrypt.Loadkey(peerPub, nil); err != nil {
		return nil, err
	}

	headData, err := o.wrapEncHead()
	if err != nil {
		return nil, err
	}

	if method == "rsa1" || method == "rsa2" {
		// RSA Hybrid: Encrypt Key with RSA, Data with AES
		hkey := Bencrypt.Random(44)
		o.MsgInfo, err = amEncrypt.Encrypt(hkey)
		if err != nil {
			return nil, err
		}
		sm := new(Bencrypt.SymMaster)
		if err := sm.Init("gcm1", hkey); err != nil {
			return nil, err
		}
		o.encHeadData, err = sm.EnBin(headData)
		if err != nil {
			return nil, err
		}

	} else {
		o.encHeadData, err = amEncrypt.Encrypt(headData)
		if err != nil {
			return nil, err
		}
	}

	// Wrap outer header
	cfg := make(map[string][]byte)
	if o.Msg != "" {
		cfg["msg"] = []byte(o.Msg)
	}
	if len(o.MsgInfo) > 0 {
		cfg["minf"] = o.MsgInfo
	}
	cfg["hal"] = []byte(o.headAlgo)
	cfg["ehd"] = o.encHeadData
	return EncodeCfg(cfg)
}

// Load outer layer of header
func (o *Opsec) View(data []byte) {
	o.Reset()
	cfg := DecodeCfg(data)
	if v, ok := cfg["msg"]; ok {
		o.Msg = string(v)
	}
	if v, ok := cfg["minf"]; ok {
		o.MsgInfo = v
	}
	if v, ok := cfg["hal"]; ok {
		o.headAlgo = string(v)
	}
	if v, ok := cfg["salt"]; ok {
		o.salt = v
	}
	if v, ok := cfg["pwh"]; ok {
		o.pwHash = v
	}
	if v, ok := cfg["ehd"]; ok {
		o.encHeadData = v
	}
}

// Decrypt with password
func (o *Opsec) Decpw(pw []byte, kf []byte) error {
	if o.headAlgo == "" {
		return errors.New("call View() first")
	}

	combinedPw := make([]byte, 0, len(pw)+len(kf))
	combinedPw = append(combinedPw, pw...)
	combinedPw = append(combinedPw, kf...)

	// KDF via HashMaster
	hm := new(Bencrypt.HashMaster)
	if err := hm.Init(o.headAlgo, 32, 44); err != nil {
		return err
	}
	calcHash, hkey, err := hm.KDF(combinedPw, o.salt)
	if err != nil {
		return err
	}

	// Constant time comparison
	if subtle.ConstantTimeCompare(calcHash, o.pwHash) != 1 {
		return errors.New("incorrect password")
	}

	// Decrypt header
	sm := new(Bencrypt.SymMaster)
	if err := sm.Init("gcm1", hkey); err != nil {
		return err
	}
	decryptedHead, err := sm.DeBin(o.encHeadData)
	if err != nil {
		return fmt.Errorf("AES decryption failed: %w", err)
	}
	o.unwrapEncHead(decryptedHead)
	return nil
}

// Decrypt with private key, verify if public key is not nil
func (o *Opsec) Decpub(myPri []byte, myPub []byte, peerPub []byte) error {
	if o.headAlgo == "" {
		return errors.New("call View() first")
	}

	// Init AsymMaster
	am := new(Bencrypt.AsymMaster)
	if err := am.Init(o.headAlgo); err != nil {
		return err
	}
	if err := am.Loadkey(nil, myPri); err != nil {
		return err
	}

	// Decrypt header
	var decryptedHead []byte
	var err error

	if o.headAlgo == "rsa1" || o.headAlgo == "rsa2" {
		// RSA Hybrid
		hkey, err := am.Decrypt(o.MsgInfo)
		if err != nil {
			return fmt.Errorf("RSA decryption failed: %w", err)
		}
		sm := new(Bencrypt.SymMaster)
		if err := sm.Init("gcm1", hkey); err != nil {
			return err
		}
		decryptedHead, err = sm.DeBin(o.encHeadData)
		if err != nil {
			return fmt.Errorf("AES decryption failed: %w", err)
		}

	} else {
		decryptedHead, err = am.Decrypt(o.encHeadData)
		if err != nil {
			return fmt.Errorf("Asymmetric decryption failed: %w", err)
		}
	}
	o.unwrapEncHead(decryptedHead)

	// Verify if public keys are provided
	if myPub == nil && peerPub == nil {
		return nil
	}
	if myPub == nil || peerPub == nil {
		if len(o.sign) > 0 {
			return errors.New("both myPub and peerPub should be provided to verify sign")
		}
		return nil
	}

	amVerify := new(Bencrypt.AsymMaster)
	if err := amVerify.Init(o.headAlgo); err != nil {
		return err
	}
	if err := amVerify.Loadkey(peerPub, nil); err != nil {
		return err
	}

	signTgt := make([]byte, 0)
	signTgt = append(signTgt, []byte(o.headAlgo)...)
	signTgt = append(signTgt, myPub...)
	signTgt = append(signTgt, []byte(o.Smsg)...)
	signTgt = append(signTgt, o.SmsgInfo...)

	if !amVerify.Verify(signTgt, o.sign) {
		return errors.New("signature verification failed")
	}
	return nil
}
