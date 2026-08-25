//go:build !linux

package server

import (
	"errors"
	"net/http"
)

type ptyHooks struct {
	Output func([]byte)
}

func servePTY(w http.ResponseWriter, r *http.Request, cwd string, extraEnv map[string]string, hooks ptyHooks) error {
	return errors.New("PTY terminal is supported on Linux only")
}
