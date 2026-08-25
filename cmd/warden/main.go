package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/warden-app/warden/internal/server"
)

const version = "0.1.0-dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "hash-password" {
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "usage: warden hash-password <password>")
			os.Exit(2)
		}
		h, err := hashPassword(os.Args[2])
		if err != nil {
			fatal(err)
		}
		fmt.Println(h)
		return
	}
	fs := flag.NewFlagSet("warden", flag.ExitOnError)
	configDir := fs.String("config", server.DefaultConfigDir(), "Warden configuration directory")
	listen := fs.String("listen", env("WARDEN_LISTEN", "127.0.0.1:8080"), "listen address used when creating a new config")
	root := fs.String("root", env("WARDEN_FILE_ROOT", "/"), "filesystem root used when creating a new config (terminal is not sandboxed by this)")
	static := fs.String("static", env("WARDEN_STATIC_DIR", "public"), "Nift-built frontend directory used when creating a new config")
	fs.Parse(os.Args[1:])
	pass := os.Getenv("WARDEN_PASSWORD_HASH") // optional legacy verifier used to authorize browser migration
	secureDefault := !isLoopbackListen(*listen)
	defaults := server.Config{Listen: *listen, FileRoot: *root, HomeDir: home(), StaticDir: *static, PasswordHash: pass, Version: version, ConfigDir: *configDir, SecureCookies: envBool("WARDEN_SECURE_COOKIES", secureDefault), TrustProxy: envBool("WARDEN_TRUST_PROXY", false)}
	cfg, err := server.LoadConfig(*configDir, defaults)
	if err != nil {
		fatal(err)
	}
	if err := server.Run(cfg); err != nil {
		fatal(err)
	}
}
func home() string {
	h, _ := os.UserHomeDir()
	if h == "" {
		return "/"
	}
	return h
}
func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func isLoopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
func envBool(k string, d bool) bool {
	v := os.Getenv(k)
	if v == "" {
		return d
	}
	b, e := strconv.ParseBool(v)
	if e != nil {
		return d
	}
	return b
}
func fatal(err error) { fmt.Fprintln(os.Stderr, "warden:", err); os.Exit(1) }
func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		return "", e
	}
	iter := 310000
	dk := pbkdf2([]byte(password), salt, iter, 32)
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", iter, hex.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(dk)), nil
}
func pbkdf2(p, s []byte, iter, n int) []byte { // PBKDF2-HMAC-SHA256, dependency-free
	out := make([]byte, 0, n)
	for block := 1; len(out) < n; block++ {
		var ctr [4]byte
		ctr[0] = byte(block >> 24)
		ctr[1] = byte(block >> 16)
		ctr[2] = byte(block >> 8)
		ctr[3] = byte(block)
		u := hmac256(p, append(append([]byte{}, s...), ctr[:]...))
		t := append([]byte{}, u...)
		for i := 1; i < iter; i++ {
			u = hmac256(p, u)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:n]
}
func hmac256(k, m []byte) []byte {
	if len(k) > 64 {
		x := sha256.Sum256(k)
		k = x[:]
	}
	kb := make([]byte, 64)
	copy(kb, k)
	ipad := make([]byte, 64)
	opad := make([]byte, 64)
	for i := range kb {
		ipad[i] = kb[i] ^ 0x36
		opad[i] = kb[i] ^ 0x5c
	}
	a := sha256.Sum256(append(ipad, m...))
	b := sha256.Sum256(append(opad, a[:]...))
	return b[:]
}

var _ = subtle.ConstantTimeCompare
var _ = strings.TrimSpace
