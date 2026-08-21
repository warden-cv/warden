//go:build !linux

package server

import (
	"errors"
	"net/http"
)

func servePTY(w http.ResponseWriter, r *http.Request, cwd string) error {
	return errors.New("PTY terminal is supported on Linux only")
}
