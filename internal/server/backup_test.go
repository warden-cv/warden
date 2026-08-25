package server

import "testing"

func TestEncryptedBackupRoundTrip(t *testing.T) {
	payload := portableSecretPayload{
		Configuration: portableConfigBundle{Version: 1},
		Secrets:       map[string]string{"google.client_secret": "google-secret", "ai.shared.openai": "openai-secret"},
	}
	backup, err := encryptPortableBackup("correct horse battery staple", payload)
	if err != nil {
		t.Fatal(err)
	}
	if backup.Ciphertext == "" || backup.Salt == "" || backup.Nonce == "" {
		t.Fatal("encrypted backup is incomplete")
	}
	got, err := decryptPortableBackup("correct horse battery staple", backup)
	if err != nil {
		t.Fatal(err)
	}
	if got.Secrets["google.client_secret"] != "google-secret" || got.Secrets["ai.shared.openai"] != "openai-secret" {
		t.Fatalf("round trip secrets = %#v", got.Secrets)
	}
	if _, err := decryptPortableBackup("wrong password", backup); err == nil {
		t.Fatal("wrong password decrypted backup")
	}
}

func TestEncryptedBackupRequiresStrongEnoughPassword(t *testing.T) {
	if _, err := encryptPortableBackup("short", portableSecretPayload{}); err == nil {
		t.Fatal("expected short backup password to fail")
	}
}
