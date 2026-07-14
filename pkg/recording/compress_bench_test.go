package recording

import (
	"testing"
)

func BenchmarkMaybeCompressGzip(b *testing.B) {
	plain := make([]byte, 64*1024)
	for i := range plain {
		plain[i] = byte('a' + i%26)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := maybeCompress(plain, "gzip"); err != nil {
			b.Fatal(err)
		}
	}
}
