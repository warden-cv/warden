package server

import (
    "testing"
    "time"
)

func TestTOTPKnownVector(t *testing.T) {
    // RFC 6238 SHA-1 secret, tested at 59 seconds; 8-digit vector is 94287082,
    // therefore the six-digit truncation is 287082.
    secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    at := time.Unix(59, 0)
    got, err := totpCode(secret, at); if err != nil { t.Fatal(err) }
    if got != "287082" { t.Fatalf("got %s", got) }
    if !verifyTOTP(secret, got, at) { t.Fatal("valid code rejected") }
    if verifyTOTP(secret, "000000", at) { t.Fatal("invalid code accepted") }
}

func TestRecoveryCodesAreOneWayAndUnique(t *testing.T) {
    codes, hashes, err := newRecoveryCodes(8); if err != nil { t.Fatal(err) }
    if len(codes) != 8 || len(hashes) != 8 { t.Fatal("wrong recovery code count") }
    seen := map[string]bool{}
    for i, c := range codes { if seen[c] { t.Fatal("duplicate code") }; seen[c]=true; if recoveryCodeHash(c) != hashes[i] { t.Fatal("hash mismatch") } }
}
