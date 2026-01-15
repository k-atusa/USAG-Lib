// test789c : USAG-Lib bencode

package bencode

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
)

// Base-N Encoder
type Bencode struct {
	chars     []rune
	revMap    map[rune]int
	Threshold int
	Escape    rune
}

func (e *Bencode) Init() {
	e.chars = make([]rune, 0, 32164)
	e.revMap = make(map[rune]int)
	e.Threshold = 32164
	e.Escape = '.'

	for i := 0; i < 11172; i++ { // 1. Korean letters
		e.chars = append(e.chars, rune(0xAC00+i))
	}
	for i := 0; i < 20992; i++ { // 2. CJK letters
		e.chars = append(e.chars, rune(0x4E00+i))
	}
	for idx, char := range e.chars { // Reverse Map
		e.revMap[char] = idx
	}
}

func (e *Bencode) Encode(data []byte, isBase64 bool) string {
	if isBase64 && len(data) == 0 {
		return ""
	}
	if isBase64 {
		return base64.StdEncoding.EncodeToString(data)
	}
	return e.encodeUnicode(data)
}

func (e *Bencode) Decode(data string) ([]byte, error) {
	data = strings.ReplaceAll(data, "\r", "")
	data = strings.ReplaceAll(data, "\n", "")
	data = strings.ReplaceAll(data, " ", "")
	if data == "" {
		return []byte{}, nil
	}

	runes := []rune(data)
	if runes[0] < 128 && runes[0] != e.Escape { // Base64 mode
		return base64.StdEncoding.DecodeString(data)
	}
	return e.decodeUnicode(runes)
}

func (e *Bencode) encodeUnicode(data []byte) string {
	var result strings.Builder
	acc := 0
	bits := 0

	for _, b := range data {
		acc = (acc << 8) | int(b)
		bits += 8
		for bits >= 15 {
			bits -= 15
			val := acc >> bits // Upper 15 bits
			if bits == 0 {     // reset acc
				acc = 0
			} else {
				acc &= (1 << bits) - 1
			}

			if val < e.Threshold { // add rune
				result.WriteRune(e.chars[val])
			} else {
				result.WriteRune(e.Escape)
				result.WriteRune(e.chars[val-e.Threshold])
			}
		}
	}

	// Pad leftover
	val := ((acc << 1) | 1) << (14 - bits)
	if val < e.Threshold {
		result.WriteRune(e.chars[val])
	} else {
		result.WriteRune(e.Escape)
		result.WriteRune(e.chars[val-e.Threshold])
	}
	return result.String()
}

func (e *Bencode) decodeUnicode(runes []rune) ([]byte, error) {
	var ba bytes.Buffer
	acc := 0
	bits := 0
	n := len(runes)
	i := 0

	for i < n {
		char := runes[i]
		i++
		val := 0

		// get rune, accumulate 15-bits
		if char == e.Escape {
			if i >= n {
				return nil, errors.New("invalid escape")
			}
			nextChar := runes[i]
			i++
			val = e.revMap[nextChar] + e.Threshold
		} else {
			val = e.revMap[char]
		}
		acc = (acc << 15) | val
		bits += 15

		for i < n && bits >= 8 {
			bits -= 8
			byteVal := byte(acc >> bits)
			if bits == 0 {
				acc = 0
			} else {
				acc &= (1 << bits) - 1
			}
			ba.WriteByte(byteVal)
		}
	}

	// Cut until last 1
	for bits > 0 && (acc&1) == 0 {
		acc >>= 1
		bits--
	}
	if bits > 0 { // cut last 1
		acc >>= 1
		bits--
	}
	for bits >= 8 {
		bits -= 8
		byteVal := byte((acc >> bits) & 0xFF)
		if bits == 0 {
			acc = 0
		} else {
			acc &= (1 << bits) - 1
		}
		ba.WriteByte(byteVal)
	}
	return ba.Bytes(), nil
}
