// test790c : USAG-Lib szip

package Szip

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Zip64 Writer
type ZipWriter struct {
	file   *os.File
	buffer *bytes.Buffer
	writer io.Writer // Abstract writer

	zip   *zip.Writer
	comp  uint16
	isMem bool
}

func (z *ZipWriter) Init(output string, compress bool) error {
	z.file = nil
	z.buffer = nil
	if output == "" { // Memory buffer
		z.buffer = new(bytes.Buffer)
		z.writer = z.buffer
		z.isMem = true
	} else { // File output
		f, err := os.Create(output)
		z.file = f
		z.writer = f
		z.isMem = false
		if err != nil {
			return err
		}
	}

	// Create zip writer
	z.zip = zip.NewWriter(z.writer)
	if compress {
		z.comp = zip.Deflate
	} else {
		z.comp = zip.Store
	}
	return nil
}

func (z *ZipWriter) WriteFile(name string, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Create zip header
	info, err := f.Stat()
	if err != nil {
		return err
	}
	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	header.Name = name
	header.Method = z.comp
	w, err := z.zip.CreateHeader(header)
	if err != nil {
		return err
	}

	// Copy file
	_, err = io.Copy(w, f)
	return err
}

func (z *ZipWriter) WriteBin(name string, data []byte) error {
	// Create zip header
	header := &zip.FileHeader{
		Name:               name,
		Method:             z.comp,
		UncompressedSize64: uint64(len(data)),
	}
	w, err := z.zip.CreateHeader(header)
	if err != nil {
		return err
	}

	// Write data
	_, err = w.Write(data)
	return err
}

func (z *ZipWriter) Close() ([]byte, error) {
	e0 := z.zip.Close()
	var e1 error = nil
	var res []byte = nil
	if z.isMem {
		res = z.buffer.Bytes()
		z.buffer = nil
	} else {
		e1 = z.file.Close()
	}
	return res, errors.Join(e0, e1)
}

// Zip64 Reader
type ZipReader struct {
	file      *os.File
	buffer    []byte
	zipReader *zip.Reader

	files []*zip.File
	Names []string
	Sizes []int64
}

func (z *ZipReader) Init(input interface{}) error {
	z.file = nil
	z.buffer = nil
	var size int64 = 0
	var readerAt io.ReaderAt

	switch v := input.(type) {
	case string: // File path input
		f, err := os.Open(v)
		if err != nil {
			return err
		}
		stat, err := f.Stat()
		if err != nil {
			f.Close()
			return err
		}
		z.file = f
		readerAt = f
		size = stat.Size()
	case []byte: // Data input
		z.buffer = v
		readerAt = bytes.NewReader(v)
		size = int64(len(v))
	default:
		return errors.New("input must be filepath(string) or data([]byte)")
	}

	// Create zip reader
	var err error
	z.zipReader, err = zip.NewReader(readerAt, size)
	if err != nil {
		if z.file != nil {
			z.file.Close()
		}
		return err
	}
	z.files = z.zipReader.File
	z.Names = make([]string, len(z.files))
	z.Sizes = make([]int64, len(z.files))
	for i, f := range z.files {
		z.Names[i] = f.Name
		z.Sizes[i] = int64(f.UncompressedSize64)
	}
	return nil
}

func (z *ZipReader) Read(idx int) ([]byte, error) {
	if idx < 0 || idx >= len(z.files) {
		return nil, errors.New("index out of bounds")
	}
	f := z.files[idx]
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

func (z *ZipReader) Open(idx int) (io.ReadCloser, error) {
	if idx < 0 || idx >= len(z.files) {
		return nil, errors.New("index out of bounds")
	}
	return z.files[idx].Open()
}

func (z *ZipReader) Close() error {
	if z.file != nil {
		return z.file.Close()
	}
	return nil
}

func Pack(srcs []string, dst string) error {
	zw := new(ZipWriter)
	if err := zw.Init(dst, true); err != nil {
		return err
	}
	defer zw.Close()

	for _, src := range srcs {
		info, err := os.Stat(src)
		if err != nil {
			return err
		}

		// Case 1: Source is a single file
		if !info.IsDir() {
			name := filepath.Base(src)
			if err := zw.WriteFile(name, src); err != nil {
				return err
			}
			continue
		}

		// Case 2: Source is a directory
		parent := filepath.Dir(filepath.Clean(src))
		err = filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(parent, path)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)

			if info.IsDir() {
				if !strings.HasSuffix(rel, "/") {
					rel += "/"
				}
				return zw.WriteBin(rel, []byte{})
			}
			return zw.WriteFile(rel, path)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func Unpack(src string, dst string) error {
	zr := new(ZipReader)
	if err := zr.Init(src); err != nil {
		return err
	}
	defer zr.Close()

	for i, name := range zr.Names {
		// Normalize path separators
		relPath := filepath.ToSlash(name)
		target := filepath.Join(dst, relPath)

		// ZipSlip Protection
		rel, err := filepath.Rel(dst, target)
		if err != nil || strings.HasPrefix(rel, "..") {
			return fmt.Errorf("illegal file path: %s", name)
		}

		if strings.HasSuffix(relPath, "/") { // Create directory
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}

		} else { // Create file
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			fOut, err := os.Create(target)
			if err != nil {
				return err
			}
			rc, err := zr.Open(i)
			if err != nil {
				fOut.Close()
				return err
			}

			_, err = io.Copy(fOut, rc)
			fOut.Close()
			rc.Close()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// UnpackMem is helper for in-memory unpacking
func UnpackMem(src []byte, sizeLimit int64) (map[string][]byte, error) {
	zr := new(ZipReader)
	if err := zr.Init(src); err != nil {
		return nil, err
	}
	defer zr.Close()

	res := make(map[string][]byte)
	for i, name := range zr.Names {
		if strings.HasSuffix(name, "/") {
			continue // skip directories in memory unpacking
		}

		if zr.Sizes[i] > sizeLimit {
			res[name] = nil // indicate file is too large
		} else {
			data, err := zr.Read(i)
			if err != nil {
				return nil, err
			}
			res[name] = data
		}
	}
	return res, nil
}
