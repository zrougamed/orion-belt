package recording

import (
	"bytes"
	"testing"
)

func TestMaybeCompressRoundTrip(t *testing.T) {
	plain := []byte("{\"version\":2}\n[0,\"o\",\"hi\"]\n")
	gz, err := maybeCompress(plain, "gzip")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(gz, []byte(gzipMagic)) {
		t.Fatalf("missing magic: %q", gz[:min(8, len(gz))])
	}
	out, err := MaybeDecompress(gz)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, plain) {
		t.Fatalf("round-trip mismatch: %q vs %q", out, plain)
	}
}

func TestMaybeDecompressPlain(t *testing.T) {
	plain := []byte("not compressed")
	out, err := MaybeDecompress(plain)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, plain) {
		t.Fatal("plain data should pass through")
	}
}

func TestMaybeCompressNone(t *testing.T) {
	plain := []byte("plain cast")
	out, err := maybeCompress(plain, "none")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, plain) {
		t.Fatal("none should skip compression")
	}
}
