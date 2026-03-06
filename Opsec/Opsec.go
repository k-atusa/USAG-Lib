// test794bc : USAG-Lib opsec

package Opsec

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
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

/*
Opsec header handler, !!! DO NOT REUSE THIS OBJECT !!! reset after reading body key
pw: (msg), headAlgo, salt, pwHash, encHeadData
rsa: (msg), headAlgo, encHeadKey, encHeadData
ecc: (msg), headAlgo, encHeadData
header: (smsg), (size), (name), (bodyKey), (bodyAlgo), (contAlgo), (sign)
*/
type Opsec struct {
	// Outer Layer
	Msg         string // non-secured message
	headAlgo    string // header algorithm, [arg1 pbk1 rsa1 ecc1]
	salt        []byte // salt
	pwHash      []byte // pw hash
	encHeadKey  []byte // encrypted header key
	encHeadData []byte // encrypted header data

	// Inner Layer
	Smsg     string // secured message
	Size     int64  // full body size, flag for bodyKey generation
	Name     string // body name
	BodyKey  []byte // body key
	BodyAlgo string // body algorithm, [gcm1 gcmx1]
	ContAlgo string // container algorithm, [zip1 tar1]
	sign     []byte // signature to bodyKey/smsg
}

// Reset all fields
func (o *Opsec) Reset() {
	o.Msg = ""
	o.headAlgo = ""
	o.salt = []byte{}
	o.pwHash = []byte{}
	o.encHeadKey = []byte{}
	o.encHeadData = []byte{}

	o.Smsg = ""
	o.Size = -1
	o.Name = ""
	o.BodyKey = []byte{}
	o.BodyAlgo = ""
	o.ContAlgo = ""
	o.sign = []byte{}
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

func (o *Opsec) wrapHead() ([]byte, error) {
	cfg := make(map[string][]byte)
	if o.Smsg != "" {
		cfg["smsg"] = []byte(o.Smsg)
	}
	if o.Size >= 0 {
		var szBytes []byte
		if o.Size < 65536 {
			szBytes = EncodeInt(uint64(o.Size), 2)
		} else if o.Size < 4294967296 {
			szBytes = EncodeInt(uint64(o.Size), 4)
		} else {
			szBytes = EncodeInt(uint64(o.Size), 8)
		}
		cfg["sz"] = szBytes
	}
	if o.Name != "" {
		cfg["nm"] = []byte(o.Name)
	}
	if len(o.BodyKey) > 0 {
		cfg["bkey"] = o.BodyKey
	}
	if o.BodyAlgo != "" {
		cfg["bodyal"] = []byte(o.BodyAlgo)
	}
	if o.ContAlgo != "" {
		cfg["contal"] = []byte(o.ContAlgo)
	}
	if len(o.sign) > 0 {
		cfg["sgn"] = o.sign
	}
	return EncodeCfg(cfg)
}

func (o *Opsec) unwrapHead(data []byte) {
	cfg := DecodeCfg(data)
	if v, ok := cfg["smsg"]; ok {
		o.Smsg = string(v)
	}
	if v, ok := cfg["sz"]; ok {
		o.Size = int64(DecodeInt(v))
	}
	if v, ok := cfg["nm"]; ok {
		o.Name = string(v)
	}
	if v, ok := cfg["bkey"]; ok {
		o.BodyKey = v
	}
	if v, ok := cfg["bodyal"]; ok {
		o.BodyAlgo = string(v)
	}
	if v, ok := cfg["contal"]; ok {
		o.ContAlgo = string(v)
	}
	if v, ok := cfg["sgn"]; ok {
		o.sign = v
	}
}

// Encrypt with password
func (o *Opsec) Encpw(method string, pw []byte, kf []byte) ([]byte, error) {
	// set basic parameters
	o.headAlgo = method
	o.salt = Bencrypt.Random(16)
	if o.Size >= 0 {
		o.BodyKey = Bencrypt.Random(44)
	}

	// Combine pw + kf
	combinedPw := make([]byte, len(pw)+len(kf))
	copy(combinedPw, pw)
	copy(combinedPw[len(pw):], kf)

	// Generate password hash
	var mkey []byte
	var err error
	switch method {
	case "sha3":
		mkey = Bencrypt.SHA3512(append(o.salt, combinedPw...))
		o.pwHash, err = Bencrypt.Genkey(mkey, "PWHASH_OPSEC_SHA3512", 32)
	case "pbk1":
		mkey = Bencrypt.Pbkdf2(combinedPw, o.salt, 1000000, 64)
		o.pwHash, err = Bencrypt.Genkey(mkey, "PWHASH_OPSEC_PBKDF2", 32)
	case "arg1":
		mkey = []byte(Bencrypt.Argon2Hash(combinedPw, o.salt))
		o.pwHash, err = Bencrypt.Genkey(mkey, "PWHASH_OPSEC_ARGON2", 32)
	default:
		return nil, errors.New("unsupported method: " + method)
	}
	if err != nil {
		return nil, err
	}

	// Generate header key
	var hkey [44]byte
	var hkey_t []byte
	switch method {
	case "sha3":
		hkey_t, err = Bencrypt.Genkey(mkey, "KEYGEN_OPSEC_SHA3512", 44)
	case "pbk1":
		hkey_t, err = Bencrypt.Genkey(mkey, "KEYGEN_OPSEC_PBKDF2", 44)
	case "arg1":
		hkey_t, err = Bencrypt.Genkey(mkey, "KEYGEN_OPSEC_ARGON2", 44)
	default:
		return nil, errors.New("unsupported method: " + method)
	}
	copy(hkey[:], hkey_t)
	if err != nil {
		return nil, err
	}

	// Encrypt header
	headData, err := o.wrapHead()
	if err != nil {
		return nil, err
	}
	sm := new(Bencrypt.SymMaster)
	sm.Init("gcm1", hkey[:])
	o.encHeadData, err = sm.EnBin(headData)
	if err != nil {
		return nil, err
	}

	// wrap header
	cfg := make(map[string][]byte)
	if o.Msg != "" {
		cfg["msg"] = []byte(o.Msg)
	}
	cfg["headal"] = []byte(o.headAlgo)
	cfg["salt"] = o.salt
	cfg["pwh"] = o.pwHash
	cfg["ehd"] = o.encHeadData
	return EncodeCfg(cfg)
}

// Encrypt with public key, sign if private key is not nil
func (o *Opsec) Encpub(method string, public []byte, private []byte) ([]byte, error) {
	// set basic parameters
	o.headAlgo = method
	if o.Size >= 0 {
		o.BodyKey = Bencrypt.Random(44)
	}

	// Init AsymMaster
	am := new(Bencrypt.AsymMaster)
	if err := am.Init(method); err != nil {
		return nil, err
	}
	if err := am.Loadkey(public, private); err != nil {
		return nil, err
	}

	// Sign if private key is not nil
	if private != nil {
		s := o.BodyKey
		if len(s) == 0 && o.Smsg != "" {
			s = []byte(o.Smsg)
		}
		var err error
		o.sign, err = am.Sign(s)
		if err != nil {
			return nil, err
		}
	}

	// Encrypt header
	headData, err := o.wrapHead()
	if err != nil {
		return nil, err
	}
	var encHeadData []byte
	switch method {
	case "rsa1", "rsa2":
		// RSA Hybrid: Encrypt Key with RSA, Data with AES
		var hkey [44]byte
		copy(hkey[:], Bencrypt.Random(44))
		o.encHeadKey, err = am.Encrypt(hkey[:])
		if err != nil {
			return nil, err
		}
		sm := new(Bencrypt.SymMaster)
		sm.Init("gcm1", hkey[:])
		encHeadData, err = sm.EnBin(headData)
		if err != nil {
			return nil, err
		}
	case "ecc1":
		encHeadData, err = am.Encrypt(headData)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unsupported method: " + method)
	}
	o.encHeadData = encHeadData

	// wrap header
	cfg := make(map[string][]byte)
	if o.Msg != "" {
		cfg["msg"] = []byte(o.Msg)
	}
	cfg["headal"] = []byte(o.headAlgo)
	if len(o.encHeadKey) > 0 {
		cfg["ehk"] = o.encHeadKey
	}
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
	if v, ok := cfg["headal"]; ok {
		o.headAlgo = string(v)
	}
	if v, ok := cfg["salt"]; ok {
		o.salt = v
	}
	if v, ok := cfg["pwh"]; ok {
		o.pwHash = v
	}
	if v, ok := cfg["ehk"]; ok {
		o.encHeadKey = v
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

	// Combine pw + kf
	combinedPw := make([]byte, len(pw)+len(kf))
	copy(combinedPw, pw)
	copy(combinedPw[len(pw):], kf)

	// Generate password hash
	var mkey []byte
	var verifyLbl, keygenLbl string
	switch o.headAlgo {
	case "sha3":
		mkey = Bencrypt.SHA3512(append(o.salt, combinedPw...))
		verifyLbl = "PWHASH_OPSEC_SHA3512"
		keygenLbl = "KEYGEN_OPSEC_SHA3512"
	case "pbk1":
		mkey = Bencrypt.Pbkdf2(combinedPw, o.salt, 1000000, 64)
		verifyLbl = "PWHASH_OPSEC_PBKDF2"
		keygenLbl = "KEYGEN_OPSEC_PBKDF2"
	case "arg1":
		hashStr := Bencrypt.Argon2Hash(combinedPw, o.salt)
		mkey = []byte(hashStr)
		verifyLbl = "PWHASH_OPSEC_ARGON2"
		keygenLbl = "KEYGEN_OPSEC_ARGON2"
	default:
		return errors.New("unsupported method: " + o.headAlgo)
	}

	// Check password
	calcHash, err := Bencrypt.Genkey(mkey, verifyLbl, 32)
	if err != nil {
		return err
	}
	if !bytes.Equal(calcHash, o.pwHash) {
		return errors.New("incorrect password")
	}

	// Decrypt header
	hkey_t, err := Bencrypt.Genkey(mkey, keygenLbl, 44)
	if err != nil {
		return err
	}
	var hkey [44]byte
	copy(hkey[:], hkey_t)
	sm := new(Bencrypt.SymMaster)
	sm.Init("gcm1", hkey[:])
	decryptedHead, err := sm.DeBin(o.encHeadData)
	if err != nil {
		return errors.New("AES decryption failed")
	}
	o.unwrapHead(decryptedHead)
	return nil
}

// Decrypt with private key, verify if public key is not nil
func (o *Opsec) Decpub(private []byte, public []byte) error {
	if o.headAlgo == "" {
		return errors.New("call View() first")
	}

	// Init AsymMaster
	am := new(Bencrypt.AsymMaster)
	if err := am.Init(o.headAlgo); err != nil {
		return err
	}
	if err := am.Loadkey(public, private); err != nil {
		return err
	}

	// Decrypt header
	var decryptedHead []byte
	var err error
	switch o.headAlgo {
	case "rsa1", "rsa2":
		hkey_t, err := am.Decrypt(o.encHeadKey)
		if err != nil {
			return errors.New("RSA decryption failed")
		}
		var hkey [44]byte
		copy(hkey[:], hkey_t)
		sm := new(Bencrypt.SymMaster)
		sm.Init("gcm1", hkey[:])
		decryptedHead, err = sm.DeBin(o.encHeadData)
		if err != nil {
			return errors.New("AES decryption failed")
		}
	case "ecc1":
		decryptedHead, err = am.Decrypt(o.encHeadData)
		if err != nil {
			return errors.New("ECC decryption failed")
		}
	default:
		return errors.New("unsupported method: " + o.headAlgo)
	}
	o.unwrapHead(decryptedHead)

	// Verify if public key is not nil
	if public != nil {
		s := o.BodyKey
		if len(s) == 0 && o.Smsg != "" {
			s = []byte(o.Smsg)
		}
		if !am.Verify(s, o.sign) {
			return errors.New("signature verification failed")
		}
	}
	return nil
}
