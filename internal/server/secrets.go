package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type encryptedSecret struct {
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type secretsFile struct {
	Version int                        `json:"version"`
	Values  map[string]encryptedSecret `json:"values"`
}

type secretStore struct {
	mu   sync.RWMutex
	dir  string
	key  []byte
	data secretsFile
}

func loadSecretStore(dir string) (*secretStore, error) {
	keyPath := filepath.Join(dir, "master.key")
	key, err := os.ReadFile(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		key = make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return nil, err
		}
		if err = os.WriteFile(keyPath, key, 0600); err != nil {
			return nil, fmt.Errorf("write master key: %w", err)
		}
	} else if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("master.key must contain exactly 32 bytes")
	}
	if err := os.Chmod(keyPath, 0600); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "secrets.json")
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := writeJSONAtomic(path, secretsFile{Version: configSchemaVersion, Values: map[string]encryptedSecret{}}, false); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	s := &secretStore{dir: dir, key: append([]byte(nil), key...)}
	if err := s.reload(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *secretStore) readCandidate() (secretsFile, error) {
	var next secretsFile
	if err := readJSONStrict(filepath.Join(s.dir, "secrets.json"), &next); err != nil {
		return next, fmt.Errorf("secrets.json: %w", err)
	}
	if next.Version != configSchemaVersion {
		return next, fmt.Errorf("secrets.json: unsupported schema version %d", next.Version)
	}
	if next.Values == nil {
		next.Values = map[string]encryptedSecret{}
	}
	for name, v := range next.Values {
		if name == "" {
			return next, errors.New("secrets.json: empty secret name")
		}
		if _, err := s.decrypt(v); err != nil {
			return next, fmt.Errorf("secrets.json: secret %q cannot be decrypted: %w", name, err)
		}
	}
	return next, nil
}

func (s *secretStore) applyCandidate(next secretsFile) {
	s.mu.Lock()
	s.data = next
	s.mu.Unlock()
}

func (s *secretStore) reload() error {
	next, err := s.readCandidate()
	if err != nil {
		return err
	}
	s.applyCandidate(next)
	return nil
}

func (s *secretStore) encrypt(value string) (encryptedSecret, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return encryptedSecret{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return encryptedSecret{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return encryptedSecret{}, err
	}
	sealed := gcm.Seal(nil, nonce, []byte(value), nil)
	return encryptedSecret{Nonce: base64.RawStdEncoding.EncodeToString(nonce), Ciphertext: base64.RawStdEncoding.EncodeToString(sealed)}, nil
}

func (s *secretStore) decrypt(v encryptedSecret) (string, error) {
	nonce, err := base64.RawStdEncoding.DecodeString(v.Nonce)
	if err != nil {
		return "", err
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(v.Ciphertext)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(nonce) != gcm.NonceSize() {
		return "", errors.New("invalid nonce size")
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func (s *secretStore) get(name string) (string, bool) {
	s.mu.RLock()
	v, ok := s.data.Values[name]
	s.mu.RUnlock()
	if !ok {
		return "", false
	}
	plain, err := s.decrypt(v)
	return plain, err == nil
}

func (s *secretStore) set(name, value string) error {
	if name == "" {
		return errors.New("secret name is required")
	}
	enc, err := s.encrypt(value)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := secretsFile{Version: configSchemaVersion, Values: make(map[string]encryptedSecret, len(s.data.Values)+1)}
	for k, v := range s.data.Values {
		next.Values[k] = v
	}
	next.Values[name] = enc
	if err := writeJSONAtomic(filepath.Join(s.dir, "secrets.json"), next, true); err != nil {
		return err
	}
	s.data = next
	return nil
}

func (s *secretStore) delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data.Values[name]; !ok {
		return nil
	}
	next := secretsFile{Version: configSchemaVersion, Values: make(map[string]encryptedSecret, len(s.data.Values)-1)}
	for k, v := range s.data.Values {
		if k != name {
			next.Values[k] = v
		}
	}
	if err := writeJSONAtomic(filepath.Join(s.dir, "secrets.json"), next, true); err != nil {
		return err
	}
	s.data = next
	return nil
}

func (s *secretStore) deletePrefix(prefix string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := secretsFile{Version: configSchemaVersion, Values: map[string]encryptedSecret{}}
	changed := false
	for k, v := range s.data.Values {
		if strings.HasPrefix(k, prefix) {
			changed = true
			continue
		}
		next.Values[k] = v
	}
	if !changed {
		return nil
	}
	if err := writeJSONAtomic(filepath.Join(s.dir, "secrets.json"), next, true); err != nil {
		return err
	}
	s.data = next
	return nil
}

func (s *secretStore) reset() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := secretsFile{Version: configSchemaVersion, Values: map[string]encryptedSecret{}}
	if err := writeJSONAtomic(filepath.Join(s.dir, "secrets.json"), next, true); err != nil {
		return err
	}
	s.data = next
	return nil
}

func (s *secretStore) marshalForTest() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return json.Marshal(s.data)
}
