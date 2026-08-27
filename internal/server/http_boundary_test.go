package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPBoundaryRejectsEncodingAndBoundsBodies(t *testing.T) {
	h := httpBoundary(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "http://warden/api/login", strings.NewReader("{}"))
	req.Header.Set("Content-Encoding", "gzip")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("encoding status=%d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "http://warden/api/login", strings.NewReader(strings.Repeat("x", maxRequestBody+1)))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large body status=%d", rec.Code)
	}
}

func TestSecurityHeadersCoverErrors(t *testing.T) {
	h := securityHeaders(httpBoundary(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "bad", http.StatusBadRequest) })))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://warden/api/test", nil))
	for _, name := range []string{"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Permissions-Policy", "Cache-Control"} {
		if rec.Header().Get(name) == "" {
			t.Fatalf("missing %s", name)
		}
	}
}
