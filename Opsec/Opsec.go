// test794bc : USAG-Lib opsec

package Opsec

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"

	Bencrypt "github.com/k-atusa/USAG-Lib/Bencrypt"
)

// ========== Helper Functions ==========
func Crc32(data []byte) []byte {
	checksum := crc32.ChecksumIEEE(data)
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, checksum)
	return buf
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
	HeadAlgo    string // header algorithm, [arg1 pbk1 rsa1 ecc1]
	Salt        []byte // salt
	PwHash      []byte // pw hash
	EncHeadKey  []byte // encrypted header key
	EncHeadData []byte // encrypted header data

	// Inner Layer
	Smsg     string // secured message
	Size     int    // full body size, flag for bodyKey generation
	Name     string // body name
	BodyKey  []byte // body key
	BodyAlgo string // body algorithm, [gcm1 gcmx1]
	ContAlgo string // container algorithm, [zip1 tar1]
	Sign     []byte // signature to bodyKey/smsg
}

// Reset all fields
func (o *Opsec) Reset() {
	o.Msg = ""
	o.HeadAlgo = ""
	o.Salt = []byte{}
	o.PwHash = []byte{}
	o.EncHeadKey = []byte{}
	o.EncHeadData = []byte{}

	o.Smsg = ""
	o.Size = -1
	o.Name = ""
	o.BodyKey = []byte{}
	o.BodyAlgo = ""
	o.ContAlgo = ""
	o.Sign = []byte{}
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
	if len(o.Sign) > 0 {
		cfg["sgn"] = o.Sign
	}
	return EncodeCfg(cfg)
}

func (o *Opsec) unwrapHead(data []byte) {
	cfg := DecodeCfg(data)
	if v, ok := cfg["smsg"]; ok {
		o.Smsg = string(v)
	}
	if v, ok := cfg["sz"]; ok {
		o.Size = int(DecodeInt(v))
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
		o.Sign = v
	}
}

// Encrypt with password
func (o *Opsec) Encpw(method string, pw []byte, kf []byte) ([]byte, error) {
	// set basic parameters
	if method != "arg1" && method != "pbk1" {
		return nil, errors.New("unsupported method: " + method)
	}
	o.HeadAlgo = method
	o.Salt = Bencrypt.Random(16)
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
	case "arg1":
		mkey = []byte(Bencrypt.Argon2Hash(combinedPw, o.Salt))
		o.PwHash, err = Bencrypt.Genkey(mkey, "PWHASH_OPSEC_ARGON2", 32)
	case "pbk1":
		mkey = Bencrypt.Pbkdf2(combinedPw, o.Salt, 1000000, 64)
		o.PwHash, err = Bencrypt.Genkey(mkey, "PWHASH_OPSEC_PBKDF2", 32)
	}
	if err != nil {
		return nil, err
	}

	// Generate header key
	var hkey [44]byte
	var hkey_t []byte
	switch method {
	case "arg1":
		hkey_t, err = Bencrypt.Genkey(mkey, "KEYGEN_OPSEC_ARGON2", 44)
	case "pbk1":
		hkey_t, err = Bencrypt.Genkey(mkey, "KEYGEN_OPSEC_PBKDF2", 44)
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
	m := new(Bencrypt.AES1)
	o.EncHeadData, err = m.EnAESGCM(hkey, headData)
	if err != nil {
		return nil, err
	}

	// wrap header
	cfg := make(map[string][]byte)
	if o.Msg != "" {
		cfg["msg"] = []byte(o.Msg)
	}
	cfg["headal"] = []byte(o.HeadAlgo)
	cfg["salt"] = o.Salt
	cfg["pwh"] = o.PwHash
	cfg["ehd"] = o.EncHeadData
	return EncodeCfg(cfg)
}

// Encrypt with public key, sign if private key is not nil
func (o *Opsec) Encpub(method string, public []byte, private []byte) ([]byte, error) {
	// set basic parameters
	if method != "rsa1" && method != "ecc1" {
		return nil, errors.New("unsupported method: " + method)
	}
	o.HeadAlgo = method
	if o.Size >= 0 {
		o.BodyKey = Bencrypt.Random(44)
	}

	// Sign if private key is not nil
	if private != nil {
		s := o.BodyKey
		if len(s) == 0 && o.Smsg != "" {
			s = []byte(o.Smsg)
		}
		var err error
		switch method {
		case "rsa1":
			m := new(Bencrypt.RSA1)
			if err := m.Loadkey(nil, private); err != nil {
				return nil, err
			}
			o.Sign, err = m.Sign(s)
		case "ecc1":
			m := new(Bencrypt.ECC1)
			if err := m.Loadkey(nil, private); err != nil {
				return nil, err
			}
			o.Sign, err = m.Sign(s)
		}
		if err != nil {
			return nil, err
		}
	}

	// Encrypt header
	headData, err := o.wrapHead()
	if err != nil {
		return nil, err
	}
	switch method {
	case "rsa1":
		m := new(Bencrypt.RSA1)
		if err := m.Loadkey(public, nil); err != nil {
			return nil, err
		}
		var hkey [44]byte
		copy(hkey[:], Bencrypt.Random(44))
		o.EncHeadKey, err = m.Encrypt(hkey[:])
		if err != nil {
			return nil, err
		}
		aes := new(Bencrypt.AES1)
		o.EncHeadData, err = aes.EnAESGCM(hkey, headData)
		if err != nil {
			return nil, err
		}
	case "ecc1":
		m := new(Bencrypt.ECC1)
		if err := m.Loadkey(public, nil); err != nil {
			return nil, err
		}
		o.EncHeadData, err = m.Encrypt(headData)
		if err != nil {
			return nil, err
		}
	}

	// wrap header
	cfg := make(map[string][]byte)
	if o.Msg != "" {
		cfg["msg"] = []byte(o.Msg)
	}
	cfg["headal"] = []byte(o.HeadAlgo)
	if len(o.EncHeadKey) > 0 {
		cfg["ehk"] = o.EncHeadKey
	}
	cfg["ehd"] = o.EncHeadData
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
		o.HeadAlgo = string(v)
	}
	if v, ok := cfg["salt"]; ok {
		o.Salt = v
	}
	if v, ok := cfg["pwh"]; ok {
		o.PwHash = v
	}
	if v, ok := cfg["ehk"]; ok {
		o.EncHeadKey = v
	}
	if v, ok := cfg["ehd"]; ok {
		o.EncHeadData = v
	}
}

// Decrypt with password
func (o *Opsec) Decpw(pw []byte, kf []byte) error {
	if o.HeadAlgo == "" {
		return errors.New("call View() first")
	}
	if o.HeadAlgo != "arg1" && o.HeadAlgo != "pbk1" {
		return errors.New("unsupported method: " + o.HeadAlgo)
	}

	// Combine pw + kf
	combinedPw := make([]byte, len(pw)+len(kf))
	copy(combinedPw, pw)
	copy(combinedPw[len(pw):], kf)

	// Generate password hash
	var mkey []byte
	var verifyLbl, keygenLbl string
	switch o.HeadAlgo {
	case "arg1":
		hashStr := Bencrypt.Argon2Hash(combinedPw, o.Salt)
		mkey = []byte(hashStr)
		verifyLbl = "PWHASH_OPSEC_ARGON2"
		keygenLbl = "KEYGEN_OPSEC_ARGON2"
	case "pbk1":
		mkey = Bencrypt.Pbkdf2(combinedPw, o.Salt, 1000000, 64)
		verifyLbl = "PWHASH_OPSEC_PBKDF2"
		keygenLbl = "KEYGEN_OPSEC_PBKDF2"
	}

	// Check password
	calcHash, err := Bencrypt.Genkey(mkey, verifyLbl, 32)
	if err != nil {
		return err
	}
	if !bytes.Equal(calcHash, o.PwHash) {
		return errors.New("incorrect password")
	}

	// Decrypt header
	hkey_t, err := Bencrypt.Genkey(mkey, keygenLbl, 44)
	if err != nil {
		return err
	}
	var hkey [44]byte
	copy(hkey[:], hkey_t)
	m := new(Bencrypt.AES1)
	decryptedHead, err := m.DeAESGCM(hkey, o.EncHeadData)
	if err != nil {
		return err
	}
	o.unwrapHead(decryptedHead)
	return nil
}

// Decrypt with private key, verify if public key is not nil
func (o *Opsec) Decpub(private []byte, public []byte) error {
	if o.HeadAlgo == "" {
		return errors.New("call View() first")
	}
	if o.HeadAlgo != "rsa1" && o.HeadAlgo != "ecc1" {
		return errors.New("unsupported method: " + o.HeadAlgo)
	}

	// Decrypt header
	var decryptedHead []byte
	var err error
	switch o.HeadAlgo {
	case "rsa1":
		rsa := new(Bencrypt.RSA1)
		if err := rsa.Loadkey(nil, private); err != nil {
			return err
		}
		hkey_t, err := rsa.Decrypt(o.EncHeadKey)
		if err != nil {
			return errors.New("RSA decryption failed")
		}
		var hkey [44]byte
		copy(hkey[:], hkey_t)
		aes := new(Bencrypt.AES1)
		decryptedHead, err = aes.DeAESGCM(hkey, o.EncHeadData)
		if err != nil {
			return errors.New("AES decryption failed")
		}
	case "ecc1":
		ecc := new(Bencrypt.ECC1)
		if err := ecc.Loadkey(nil, private); err != nil {
			return err
		}
		decryptedHead, err = ecc.Decrypt(o.EncHeadData)
		if err != nil {
			return errors.New("ECC decryption failed")
		}
	}
	o.unwrapHead(decryptedHead)

	// Verify if public key is not nil
	if public != nil {
		s := o.BodyKey
		if len(s) == 0 && o.Smsg != "" {
			s = []byte(o.Smsg)
		}
		valid := false
		switch o.HeadAlgo {
		case "rsa1":
			m := new(Bencrypt.RSA1)
			if err := m.Loadkey(public, nil); err != nil {
				return err
			}
			valid = m.Verify(s, o.Sign)
		case "ecc1":
			m := new(Bencrypt.ECC1)
			if err := m.Loadkey(public, nil); err != nil {
				return err
			}
			valid = m.Verify(s, o.Sign)
		}
		if !valid {
			return errors.New("signature verification failed")
		}
	}
	return nil
}
