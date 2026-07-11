package recording

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zrougamed/orion-belt/pkg/common"
)

const encMagic = "OBENC1\n"

// Crypto wraps AES-256-GCM for session recordings.
type Crypto struct {
	key    []byte
	logger *common.Logger
}

// NewCrypto derives a 32-byte key from config (base64 or raw string).
func NewCrypto(keyMaterial string, logger *common.Logger) (*Crypto, error) {
	if strings.TrimSpace(keyMaterial) == "" {
		return &Crypto{logger: logger}, nil
	}
	key, err := deriveKey(keyMaterial)
	if err != nil {
		return nil, err
	}
	return &Crypto{key: key, logger: logger}, nil
}

// Enabled reports whether encryption is active.
func (c *Crypto) Enabled() bool {
	return c != nil && len(c.key) == 32
}

func deriveKey(material string) ([]byte, error) {
	if decoded, err := base64.StdEncoding.DecodeString(material); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	if len(material) == 32 {
		return []byte(material), nil
	}
	sum := sha256.Sum256([]byte(material))
	return sum[:], nil
}

// Encrypt seals plaintext with AES-GCM. Output is magic + nonce + ciphertext.
func (c *Crypto) Encrypt(plain []byte) ([]byte, error) {
	if !c.Enabled() {
		return plain, nil
	}
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	out := append([]byte(encMagic), nonce...)
	out = append(out, gcm.Seal(nil, nonce, plain, nil)...)
	return out, nil
}

// Decrypt opens an encrypted buffer (or returns as-is if not encrypted).
func (c *Crypto) Decrypt(data []byte) ([]byte, error) {
	if !strings.HasPrefix(string(data), encMagic) {
		return data, nil // plaintext legacy
	}
	if !c.Enabled() {
		return nil, fmt.Errorf("recording is encrypted but encryption_key is not configured")
	}
	payload := data[len(encMagic):]
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(payload) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := payload[:ns], payload[ns:]
	return gcm.Open(nil, nonce, ct, nil)
}

// DecryptFile reads and decrypts a recording file.
func (c *Crypto) DecryptFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return c.Decrypt(data)
}

// EncryptAndWrite encrypts content and writes to path.
func (c *Crypto) EncryptAndWrite(path string, plain []byte) error {
	out, err := c.Encrypt(plain)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0600)
}

// EnforceRetention deletes recording files older than retentionDays.
func EnforceRetention(storagePath string, retentionDays int, logger *common.Logger) (int, error) {
	if retentionDays <= 0 {
		return 0, nil
	}
	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	entries, err := os.ReadDir(storagePath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	deleted := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".txt") && !strings.HasSuffix(name, ".rec") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			path := filepath.Join(storagePath, name)
			if err := os.Remove(path); err != nil {
				if logger != nil {
					logger.Warn("retention: failed to delete %s: %v", path, err)
				}
				continue
			}
			deleted++
		}
	}
	if logger != nil && deleted > 0 {
		logger.Info("retention: deleted %d recording(s) older than %d days", deleted, retentionDays)
	}
	return deleted, nil
}
