// test792c : USAG-Lib star

package Star

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

type TarWriter struct {
	out    io.Writer
	memBuf *bytes.Buffer // Used when output is memory
	file   *os.File      // Used when output is file
}

func (tw *TarWriter) Init(output string) error {
	if output == "" { // empty string means memory
		tw.memBuf = new(bytes.Buffer)
		tw.out = tw.memBuf
	} else {
		f, err := os.Create(output)
		if err != nil {
			return err
		}
		tw.file = f
		tw.out = f
	}
	return nil
}

func (tw *TarWriter) pad(size int64) []byte {
	padSize := (512 - (size % 512)) % 512
	return make([]byte, padSize)
}

func (tw *TarWriter) tarHeader(name string, size int64, mode int, mtime int64, flag byte) []byte {
	var h [512]byte

	// Name (100)
	nameBytes := []byte(name)
	if len(nameBytes) > 100 {
		nameBytes = nameBytes[:100]
	}
	copy(h[0:], nameBytes)

	// Mode (100)
	copy(h[100:], fmt.Sprintf("%07o", mode))

	// Size (124)
	if size < 077777777777 {
		copy(h[124:], fmt.Sprintf("%011o", size))
	} else {
		copy(h[124:], "00000000000") // PAX handles real size
	}

	// Mtime (136)
	copy(h[136:], fmt.Sprintf("%011o", mtime))

	// Typeflag (156)
	h[156] = flag

	// Magic (257)
	copy(h[257:], "ustar\x00")
	copy(h[263:], "00")

	// Checksum (148) - Calc
	copy(h[148:], "        ")
	var checksum int64
	for _, b := range h {
		checksum += int64(b)
	}
	copy(h[148:], fmt.Sprintf("%06o", checksum))
	h[154] = 0
	h[155] = 32
	return h[:]
}

func (tw *TarWriter) paxHeader(name string, size int64) []byte {
	// Pax elements
	records := ""
	data := [][]string{{"path", name}, {"size", fmt.Sprintf("%d", size)}}
	for _, pair := range data {
		lineData := fmt.Sprintf(" %s=%s\n", pair[0], pair[1])
		length := len(lineData) + 1
		for { // loop until length stabilizes
			fullLine := fmt.Sprintf("%d%s", length, lineData)
			if len(fullLine) == length {
				records += fullLine
				break
			}
			length = len(fullLine)
		}
	}

	// Build PAX header block
	paxData := []byte(records)
	paxName := "PaxHeader/" + name
	header := tw.tarHeader(paxName, int64(len(paxData)), 0644, time.Now().Unix(), 'x')

	// Join: Header + Data + Pad
	buf := make([]byte, 0, 1024)
	buf = append(buf, header...)
	buf = append(buf, paxData...)
	buf = append(buf, tw.pad(int64(len(paxData)))...)
	return buf
}

func (tw *TarWriter) WriteFile(name string, path string, mode int) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	size := info.Size()

	// PAX check, Write Header
	if len(name) > 99 || size > 077777777777 {
		tw.out.Write(tw.paxHeader(name, size))
	}
	tw.out.Write(tw.tarHeader(name, size, mode, info.ModTime().Unix(), '0'))

	// Write Content
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(tw.out, f); err != nil {
		return err
	}
	tw.out.Write(tw.pad(size)) // Pad
	return nil
}

func (tw *TarWriter) WriteDir(name string, mode int) error {
	name = strings.ReplaceAll(name, "\\", "/")
	if !strings.HasSuffix(name, "/") {
		name += "/"
	}
	if len(name) > 99 { // PAX needed
		tw.out.Write(tw.paxHeader(name, 0))
	}
	tw.out.Write(tw.tarHeader(name, 0, mode, time.Now().Unix(), '5')) // ustar header
	return nil
}

func (tw *TarWriter) WriteBin(name string, data []byte, mode int) error {
	size := int64(len(data))
	if len(name) > 99 || size > 077777777777 {
		tw.out.Write(tw.paxHeader(name, size))
	}
	tw.out.Write(tw.tarHeader(name, size, mode, time.Now().Unix(), '0'))
	tw.out.Write(data)
	tw.out.Write(tw.pad(size))
	return nil
}

func (tw *TarWriter) Close() []byte {
	zeroes := make([]byte, 1024)
	tw.out.Write(zeroes) // write two empty blocks
	var res []byte = nil
	if tw.memBuf != nil {
		res = tw.memBuf.Bytes()
		tw.memBuf = nil
	}
	if tw.file != nil {
		tw.file.Close()
		tw.file = nil
	}
	return res
}

type TarReader struct {
	in     io.Reader
	memBuf *bytes.Buffer // Used when input is memory
	file   *os.File      // Used when input is file

	// Metadata
	Name  string
	Size  int64
	Mode  int
	IsDir bool
	IsEOF bool
}

func (tr *TarReader) Init(input interface{}) error {
	switch v := input.(type) {
	case string: // file path
		f, err := os.Open(v)
		if err != nil {
			return err
		}
		tr.file = f
		tr.in = f
	case []byte: // memory
		tr.memBuf = bytes.NewBuffer(v)
		tr.in = tr.memBuf
	default:
		return fmt.Errorf("unsupported source type")
	}

	tr.Name = ""
	tr.Size = 0
	tr.Mode = 0
	tr.IsDir = false
	tr.IsEOF = false
	return nil
}

func (tr *TarReader) unpad(size int64) {
	pad := (512 - (size % 512)) % 512
	if pad > 0 {
		io.CopyN(io.Discard, tr.in, int64(pad))
	}
}

func (tr *TarReader) parse(data []byte) {
	str := string(data)
	lines := strings.Split(str, "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		// "length key=value"
		parts := strings.SplitN(line, " ", 2)
		if len(parts) < 2 {
			continue
		}
		kvPart := parts[1]
		kv := strings.SplitN(kvPart, "=", 2)
		if len(kv) < 2 {
			continue
		}

		key, value := kv[0], kv[1]
		if key == "path" {
			tr.Name = value
		} else if key == "size" {
			tr.Size, _ = strconv.ParseInt(value, 10, 64)
		}
	}
}

func (tr *TarReader) Next() bool {
	if tr.IsEOF {
		return false
	}
	var h [512]byte
	n, err := io.ReadFull(tr.in, h[:])
	isZero := true // Check EOF conditions
	for _, b := range h {
		if b != 0 {
			isZero = false
			break
		}
	}
	if err == io.EOF || err == io.ErrUnexpectedEOF || n != 512 || isZero {
		tr.IsEOF = true
		io.ReadFull(tr.in, h[:]) // consume next empty block if exists
		return false
	}

	// Parse Standard Header
	tr.Name = string(bytes.Trim(h[0:100], "\x00"))
	modeStr := string(bytes.Trim(h[100:108], "\x00 ")) // Trim nulls
	ti, _ := strconv.ParseInt(modeStr, 8, 64)
	tr.Mode = int(ti)
	sizeStr := string(bytes.Trim(h[124:136], "\x00 "))
	tr.Size, _ = strconv.ParseInt(sizeStr, 8, 64)
	typeFlag := h[156]
	tr.IsDir = (typeFlag == '5')

	// PAX Handling
	if typeFlag == 'x' {
		paxData := make([]byte, tr.Size)
		io.ReadFull(tr.in, paxData)
		tr.unpad(tr.Size)

		// Parse PAX
		tr.parse(paxData)
		paxName := tr.Name
		paxSize := tr.Size
		hasNext := tr.Next()
		tr.Name = paxName
		tr.Size = paxSize
		return hasNext
	}
	return true
}

func (tr *TarReader) Read() []byte {
	data := make([]byte, tr.Size)
	io.ReadFull(tr.in, data)
	tr.unpad(tr.Size)
	return data
}

func (tr *TarReader) Mkfile(path string) error {
	if tr.IsDir {
		return os.MkdirAll(path, os.FileMode(tr.Mode))
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Copy chunked
	remaining := tr.Size
	var buf [32 * 1024]byte
	for remaining > 0 {
		toRead := int64(len(buf))
		if remaining < toRead {
			toRead = remaining
		}
		n, err := tr.in.Read(buf[:toRead])
		if n > 0 {
			f.Write(buf[:n])
			remaining -= int64(n)
		}
		if err != nil {
			break
		}
	}
	tr.unpad(tr.Size)
	return nil
}

func (tr *TarReader) Skip() {
	io.CopyN(io.Discard, tr.in, tr.Size)
	tr.unpad(tr.Size)
}

func (tr *TarReader) Close() {
	if tr.file != nil {
		tr.file.Close()
		tr.file = nil
	}
	if tr.memBuf != nil {
		tr.memBuf = nil
	}
}
