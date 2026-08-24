//go:build linux

package server

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func servePTY(w http.ResponseWriter, r *http.Request, cwd string) error {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return errors.New("websocket upgrade required")
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return errors.New("missing websocket key")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return errors.New("hijack unsupported")
	}
	conn, rw, e := hj.Hijack()
	if e != nil {
		return e
	}
	defer conn.Close()
	sum := sha1.Sum([]byte(key + wsGUID))
	accept := base64.StdEncoding.EncodeToString(sum[:])
	rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n")
	rw.Flush()
	master, slave, e := openPTY()
	if e != nil {
		return e
	}
	defer master.Close()
	defer slave.Close()
	cmd := exec.Command("/bin/bash", "-l")
	cmd.Dir = cwd
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	promptCommand := `printf '\033]777;warden-cwd=%s\007' "$PWD"`
	if existing := os.Getenv("PROMPT_COMMAND"); existing != "" {
		promptCommand += ";" + existing
	}
	cmd.Env = append(os.Environ(), "TERM=xterm-256color", "PROMPT_COMMAND="+promptCommand)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if e = cmd.Start(); e != nil {
		return e
	}
	slave.Close()
	done := make(chan struct{})
	control := &ptyControlState{shellPID: cmd.Process.Pid, done: done}
	go func() {
		buf := make([]byte, 8192)
		for {
			n, e := master.Read(buf)
			if n > 0 {
				if writeWS(conn, 1, buf[:n]) != nil {
					break
				}
			}
			if e != nil {
				break
			}
		}
		close(done)
	}()
	br := bufio.NewReader(conn)
	for {
		op, p, e := readWS(br)
		if e != nil {
			break
		}
		switch op {
		case 1, 2:
			if handled, controlErr := handlePTYControl(master, p, control); handled {
				if controlErr != nil {
					continue
				}
				continue
			}
			control.write(master, p)
		case 8:
			goto end
		case 9:
			writeWS(conn, 10, p)
		}
	}
end:
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	<-done
	return nil
}

type winsize struct {
	Row, Col, Xpixel, Ypixel uint16
}

type ptyControlState struct {
	mu       sync.Mutex
	writeMu  sync.Mutex
	pending  string
	worker   bool
	shellPID int
	done     <-chan struct{}
}

func (s *ptyControlState) write(master *os.File, p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return master.Write(p)
}

func (s *ptyControlState) writeHidden(master *os.File, p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	var term syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&term)))
	if errno != 0 {
		return 0, errno
	}
	original := term
	term.Lflag &^= syscall.ECHO | syscall.ECHONL
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&term)))
	if errno != 0 {
		return 0, errno
	}
	n, err := master.Write(p)
	_, _, restoreErrno := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&original)))
	if err != nil {
		return n, err
	}
	if restoreErrno != 0 {
		return n, restoreErrno
	}
	return n, nil
}

func (s *ptyControlState) queueCwd(master *os.File, path string) {
	s.mu.Lock()
	s.pending = path
	if s.worker {
		s.mu.Unlock()
		return
	}
	s.worker = true
	s.mu.Unlock()
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-s.done:
				s.mu.Lock()
				s.worker = false
				s.mu.Unlock()
				return
			case <-ticker.C:
				if !shellOwnsPTY(s.shellPID) {
					continue
				}
				s.mu.Lock()
				path := s.pending
				s.pending = ""
				if path == "" {
					s.worker = false
					s.mu.Unlock()
					return
				}
				s.mu.Unlock()
				cmd := "cd -- " + shellSingleQuote(path) + "\r"
				_, _ = s.writeHidden(master, []byte(cmd))
				s.mu.Lock()
				s.worker = false
				next := s.pending
				s.mu.Unlock()
				if next != "" {
					s.queueCwd(master, next)
				}
				return
			}
		}
	}()
}

func shellOwnsPTY(shellPID int) bool {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(shellPID) + "/stat")
	if err != nil {
		return false
	}
	pgid, tPGID, ok := procStatProcessGroups(string(b))
	return ok && pgid > 0 && pgid == tPGID
}

func procStatProcessGroups(stat string) (pgid, tPGID int, ok bool) {
	// comm (field 2) may contain spaces, so parse fields only after its final ')'.
	end := strings.LastIndexByte(stat, ')')
	if end < 0 || end+2 >= len(stat) {
		return 0, 0, false
	}
	fields := strings.Fields(stat[end+2:])
	// fields[2] is pgrp (stat field 5); fields[5] is tpgid (field 8).
	if len(fields) < 6 {
		return 0, 0, false
	}
	pgid, err1 := strconv.Atoi(fields[2])
	tPGID, err2 := strconv.Atoi(fields[5])
	return pgid, tPGID, err1 == nil && err2 == nil
}

func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

func handlePTYControl(master *os.File, p []byte, state *ptyControlState) (bool, error) {
	const prefix = "\x00warden:"
	if !strings.HasPrefix(string(p), prefix) {
		return false, nil
	}
	var q struct {
		Type string `json:"type"`
		Cols uint16 `json:"cols"`
		Rows uint16 `json:"rows"`
		Path string `json:"path"`
	}
	if err := json.Unmarshal(p[len(prefix):], &q); err != nil {
		return true, err
	}
	switch q.Type {
	case "resize":
		if q.Cols < 20 || q.Rows < 4 || q.Cols > 1000 || q.Rows > 1000 {
			return true, errors.New("invalid PTY size")
		}
		ws := winsize{Row: q.Rows, Col: q.Cols}
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(&ws)))
		if errno != 0 {
			return true, errno
		}
		return true, nil
	case "cwd":
		if q.Path == "" || strings.ContainsAny(q.Path, "\x00\r\n") {
			return true, errors.New("invalid PTY cwd")
		}
		state.queueCwd(master, q.Path)
		return true, nil
	default:
		return true, errors.New("unknown PTY control")
	}
}

func openPTY() (*os.File, *os.File, error) {
	m, e := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if e != nil {
		return nil, nil, e
	}
	unlock := 0
	if _, _, e1 := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(), uintptr(syscall.TIOCSPTLCK), uintptr(unsafe.Pointer(&unlock))); e1 != 0 {
		m.Close()
		return nil, nil, e1
	}
	var n uint32
	if _, _, e1 := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(), uintptr(syscall.TIOCGPTN), uintptr(unsafe.Pointer(&n))); e1 != 0 {
		m.Close()
		return nil, nil, e1
	}
	s, e := os.OpenFile("/dev/pts/"+strconv.Itoa(int(n)), os.O_RDWR|syscall.O_NOCTTY, 0)
	if e != nil {
		m.Close()
		return nil, nil, e
	}
	return m, s, nil
}
func readWS(r *bufio.Reader) (byte, []byte, error) {
	h := make([]byte, 2)
	if _, e := io.ReadFull(r, h); e != nil {
		return 0, nil, e
	}
	op := h[0] & 0xf
	masked := h[1]&0x80 != 0
	n := uint64(h[1] & 0x7f)
	if n == 126 {
		var b [2]byte
		io.ReadFull(r, b[:])
		n = uint64(binary.BigEndian.Uint16(b[:]))
	} else if n == 127 {
		var b [8]byte
		io.ReadFull(r, b[:])
		n = binary.BigEndian.Uint64(b[:])
	}
	if n > 1<<20 {
		return 0, nil, errors.New("frame too large")
	}
	var mask [4]byte
	if masked {
		io.ReadFull(r, mask[:])
	}
	p := make([]byte, n)
	if _, e := io.ReadFull(r, p); e != nil {
		return 0, nil, e
	}
	if masked {
		for i := range p {
			p[i] ^= mask[i%4]
		}
	}
	return op, p, nil
}
func writeWS(w io.Writer, op byte, p []byte) error {
	h := []byte{0x80 | op}
	n := len(p)
	if n < 126 {
		h = append(h, byte(n))
	} else if n <= 65535 {
		h = append(h, 126, byte(n>>8), byte(n))
	} else {
		h = append(h, 127, 0, 0, 0, 0, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	if _, e := w.Write(h); e != nil {
		return e
	}
	_, e := w.Write(p)
	return e
}

var _ net.Conn
