package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

const encryptedBackupFormat = "warden-encrypted-backup-v1"

type encryptedBackupFile struct {
	Format     string `json:"format"`
	KDF        string `json:"kdf"`
	Iterations int    `json:"iterations"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type portableSecretPayload struct {
	Configuration portableConfigBundle `json:"configuration"`
	Secrets       map[string]string    `json:"secrets"`
}

func backupKey(password string, salt []byte, iterations int) []byte {
	return pbkdf2([]byte(password), salt, iterations, sha256.Size)
}

func encryptPortableBackup(password string, payload portableSecretPayload) (encryptedBackupFile, error) {
	if len(password) < 10 {
		return encryptedBackupFile{}, errors.New("backup password must be at least 10 characters")
	}
	plain, err := json.Marshal(payload)
	if err != nil {
		return encryptedBackupFile{}, err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return encryptedBackupFile{}, err
	}
	iterations := 310000
	block, err := aes.NewCipher(backupKey(password, salt, iterations))
	if err != nil {
		return encryptedBackupFile{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return encryptedBackupFile{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return encryptedBackupFile{}, err
	}
	sealed := gcm.Seal(nil, nonce, plain, []byte(encryptedBackupFormat))
	return encryptedBackupFile{Format: encryptedBackupFormat, KDF: "pbkdf2-sha256", Iterations: iterations, Salt: base64.RawStdEncoding.EncodeToString(salt), Nonce: base64.RawStdEncoding.EncodeToString(nonce), Ciphertext: base64.RawStdEncoding.EncodeToString(sealed)}, nil
}

func decryptPortableBackup(password string, b encryptedBackupFile) (portableSecretPayload, error) {
	var out portableSecretPayload
	if b.Format != encryptedBackupFormat || b.KDF != "pbkdf2-sha256" || b.Iterations < 100000 || b.Iterations > 2000000 {
		return out, errors.New("unsupported encrypted Warden backup")
	}
	salt, err := base64.RawStdEncoding.DecodeString(b.Salt)
	if err != nil || len(salt) < 16 {
		return out, errors.New("invalid backup salt")
	}
	nonce, err := base64.RawStdEncoding.DecodeString(b.Nonce)
	if err != nil {
		return out, errors.New("invalid backup nonce")
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(b.Ciphertext)
	if err != nil {
		return out, errors.New("invalid backup ciphertext")
	}
	block, err := aes.NewCipher(backupKey(password, salt, b.Iterations))
	if err != nil {
		return out, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return out, err
	}
	if len(nonce) != gcm.NonceSize() {
		return out, errors.New("invalid backup nonce")
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, []byte(encryptedBackupFormat))
	if err != nil {
		return out, errors.New("incorrect backup password or corrupted backup")
	}
	if err := json.Unmarshal(plain, &out); err != nil {
		return out, errors.New("invalid encrypted backup payload")
	}
	if out.Secrets == nil {
		out.Secrets = map[string]string{}
	}
	return out, nil
}

func (a *app) exportSecureConfiguration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var q struct {
		Password string `json:"password"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&q) != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	backup, err := encryptPortableBackup(q.Password, portableSecretPayload{Configuration: a.portableConfig(), Secrets: a.secrets.exportPlain()})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a.auditEvent(r, "warden_secure_backup_export", "")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="warden-secure-backup.json"`)
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(backup)
}

func (a *app) importSecureConfiguration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var q struct {
		Password string              `json:"password"`
		Backup   encryptedBackupFile `json:"backup"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&q) != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	payload, err := decryptPortableBackup(q.Password, q.Backup)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := validatePortableBundle(payload.Configuration); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	secretFile, err := a.secrets.encryptPlain(payload.Secrets)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	b := payload.Configuration
	values := map[string]any{
		"config.json": b.Instance, "environment.json": b.Environment, "authentication.json": b.Authentication,
		"ai.json": b.AI, "users.json": b.Accounts, "roles.json": b.Roles, "secrets.json": secretFile,
	}
	if err := replaceConfigFiles(a.cfg.ConfigDir, values); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := a.reloadAllConfiguration(); err != nil {
		http.Error(w, "backup written but reload failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	a.auditEvent(r, "warden_secure_backup_import", fmt.Sprintf("exported_at=%s", b.ExportedAt.UTC().Format(time.RFC3339)))
	a.auth.revokeAll()
	jsonOut(w, map[string]any{"ok": true, "message": "Encrypted backup imported. Sign in using the restored accounts.", "reauthenticate": true})
}
