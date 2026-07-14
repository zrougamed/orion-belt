package recording

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
)

// gzipMagic marks gzip-compressed cast payloads (before optional encryption).
const gzipMagic = "OBGZ1\n"

// maybeCompress returns gzip-wrapped bytes when enabled.
func maybeCompress(plain []byte, compression string) ([]byte, error) {
	if compression == "" || compression == "gzip" {
		var buf bytes.Buffer
		buf.WriteString(gzipMagic)
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write(plain); err != nil {
			_ = zw.Close()
			return nil, err
		}
		if err := zw.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}
	if compression == "none" {
		return plain, nil
	}
	return nil, fmt.Errorf("unsupported recording compression %q (use gzip or none)", compression)
}

// MaybeDecompress unwraps OBGZ1+gzip if present; otherwise returns data unchanged.
func MaybeDecompress(data []byte) ([]byte, error) {
	if !bytes.HasPrefix(data, []byte(gzipMagic)) {
		return data, nil
	}
	zr, err := gzip.NewReader(bytes.NewReader(data[len(gzipMagic):]))
	if err != nil {
		return nil, fmt.Errorf("gzip header: %w", err)
	}
	defer zr.Close()
	out, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("gzip read: %w", err)
	}
	return out, nil
}
