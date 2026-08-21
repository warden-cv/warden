//go:build linux

package server

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
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
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if e = cmd.Start(); e != nil {
		return e
	}
	slave.Close()
	done := make(chan struct{})
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
			master.Write(p)
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
