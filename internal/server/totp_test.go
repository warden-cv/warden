package server

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTOTPKnownVector(t *testing.T) {
	// RFC 6238 SHA-1 secret, tested at 59 seconds; 8-digit vector is 94287082,
	// therefore the six-digit truncation is 287082.
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	at := time.Unix(59, 0)
	got, err := totpCode(secret, at)
	if err != nil {
		t.Fatal(err)
	}
	if got != "287082" {
		t.Fatalf("got %s", got)
	}
	if !verifyTOTP(secret, got, at) {
		t.Fatal("valid code rejected")
	}
	if verifyTOTP(secret, "000000", at) {
		t.Fatal("invalid code accepted")
	}
}

func TestRecoveryCodeCompletesLoginOnce(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{Listen: "127.0.0.1:8080", FileRoot: dir, HomeDir: dir, StaticDir: "public", ConfigDir: dir}
	config, err := loadConfigStore(dir, instanceFromConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	accounts, err := loadAccountStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	acct, err := accounts.createInitialAdmin("Admin", "admin", "administrator-password")
	if err != nil {
		t.Fatal(err)
	}
	identity := acct.Identities[0]
	const recovery = "AAAA-BBBB-CCCC"
	if err := accounts.setIdentityTOTP(acct.ID, identity.ID, true, []string{recoveryCodeHash(recovery)}); err != nil {
		t.Fatal(err)
	}
	secrets, err := loadSecretStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	files, err := newFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := &app{cfg: cfg, config: config, accounts: accounts, secrets: secrets, files: files, audit: log.New(io.Discard, "", 0)}
	a.auth = newAuth(accounts, false, dir)
	login := func(code string) int {
		challengeRequest := httptest.NewRequest(http.MethodPost, "http://warden/api/login", nil)
		challengeRequest.RemoteAddr = "127.0.0.1:1234"
		challenge := a.auth.beginChallenge(challengeRequest, acct.ID, identity.ID)
		request := httptest.NewRequest(http.MethodPost, "http://warden/api/login/totp", strings.NewReader(`{"Challenge":"`+challenge+`","Code":"`+code+`"}`))
		request.RemoteAddr = "127.0.0.1:1234"
		response := httptest.NewRecorder()
		a.loginTOTP(response, request)
		return response.Code
	}
	if status := login(recovery); status != http.StatusOK {
		t.Fatalf("recovery login status=%d", status)
	}
	if status := login(recovery); status != http.StatusUnauthorized {
		t.Fatalf("reused recovery login status=%d", status)
	}
}

func TestRecoveryCodesAreOneWayAndUnique(t *testing.T) {
	codes, hashes, err := newRecoveryCodes(8)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 8 || len(hashes) != 8 {
		t.Fatal("wrong recovery code count")
	}
	seen := map[string]bool{}
	for i, c := range codes {
		if seen[c] {
			t.Fatal("duplicate code")
		}
		seen[c] = true
		if recoveryCodeHash(c) != hashes[i] {
			t.Fatal("hash mismatch")
		}
	}
}
