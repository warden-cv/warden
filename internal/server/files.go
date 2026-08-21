package server

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type fileAPI struct{ root string }
type fileEntry struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Dir      bool   `json:"dir"`
	Size     int64  `json:"size"`
	Mode     string `json:"mode"`
	Modified int64  `json:"modified"`
}

func newFiles(root string) (*fileAPI, error) {
	abs, e := filepath.Abs(root)
	if e != nil {
		return nil, e
	}
	real, e := filepath.EvalSymlinks(abs)
	if e != nil {
		return nil, e
	}
	return &fileAPI{root: real}, nil
}
func (f *fileAPI) resolve(rel string, allowMissing bool) (string, error) {
	rel = filepath.Clean("/" + rel)
	candidate := filepath.Join(f.root, strings.TrimPrefix(rel, "/"))
	if !allowMissing {
		real, e := filepath.EvalSymlinks(candidate)
		if e != nil {
			return "", e
		}
		candidate = real
	} else {
		parent := filepath.Dir(candidate)
		real, e := filepath.EvalSymlinks(parent)
		if e != nil {
			return "", e
		}
		candidate = filepath.Join(real, filepath.Base(candidate))
	}
	r, e := filepath.Rel(f.root, candidate)
	if e != nil || r == ".." || strings.HasPrefix(r, ".."+string(os.PathSeparator)) {
		return "", errors.New("path escapes configured root")
	}
	return candidate, nil
}
func (f *fileAPI) list(w http.ResponseWriter, r *http.Request) {
	p, e := f.resolve(r.URL.Query().Get("path"), false)
	if e != nil {
		http.Error(w, e.Error(), 400)
		return
	}
	ents, e := os.ReadDir(p)
	if e != nil {
		http.Error(w, e.Error(), 400)
		return
	}
	out := make([]fileEntry, 0, len(ents))
	for _, d := range ents {
		info, e := d.Info()
		if e != nil {
			continue
		}
		rel, _ := filepath.Rel(f.root, filepath.Join(p, d.Name()))
		out = append(out, fileEntry{Name: d.Name(), Path: "/" + filepath.ToSlash(rel), Dir: d.IsDir(), Size: info.Size(), Mode: info.Mode().String(), Modified: info.ModTime().Unix()})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Dir != out[j].Dir {
			return out[i].Dir
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	jsonOut(w, out)
}
func (f *fileAPI) read(w http.ResponseWriter, r *http.Request) {
	p, e := f.resolve(r.URL.Query().Get("path"), false)
	if e != nil {
		http.Error(w, e.Error(), 400)
		return
	}
	info, e := os.Stat(p)
	if e != nil || info.IsDir() {
		http.Error(w, "not a readable file", 400)
		return
	}
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Disposition", "attachment; filename=\""+strings.ReplaceAll(filepath.Base(p), "\"", "")+"\"")
		http.ServeFile(w, r, p)
		return
	}
	if info.Size() > 2<<20 {
		http.Error(w, "file too large for editor (2 MiB limit)", 413)
		return
	}
	b, e := os.ReadFile(p)
	if e != nil {
		http.Error(w, e.Error(), 400)
		return
	}
	jsonOut(w, map[string]any{"path": r.URL.Query().Get("path"), "content": string(b), "mode": info.Mode().Perm().String(), "modified": info.ModTime().Unix()})
}
func (f *fileAPI) write(w http.ResponseWriter, r *http.Request) {
	rel := r.URL.Query().Get("path")
	p, e := f.resolve(rel, true)
	if e != nil {
		http.Error(w, e.Error(), 400)
		return
	}
	body, e := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if e != nil {
		http.Error(w, e.Error(), 400)
		return
	}
	mode := fs.FileMode(0640)
	if info, e := os.Stat(p); e == nil {
		mode = info.Mode().Perm()
	}
	tmp, e := os.CreateTemp(filepath.Dir(p), ".warden-save-*")
	if e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	name := tmp.Name()
	defer os.Remove(name)
	if e = tmp.Chmod(mode); e == nil {
		_, e = tmp.Write(body)
	}
	if e == nil {
		e = tmp.Sync()
	}
	if ce := tmp.Close(); e == nil {
		e = ce
	}
	if e == nil {
		e = os.Rename(name, p)
	}
	if e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	jsonOut(w, map[string]any{"ok": true})
}
func (f *fileAPI) mutate(w http.ResponseWriter, r *http.Request) {
	var q struct{ Op, Path, Target string }
	if json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&q) != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	p, e := f.resolve(q.Path, q.Op == "mkdir")
	if e != nil {
		http.Error(w, e.Error(), 400)
		return
	}
	if p == f.root {
		http.Error(w, "refusing to mutate configured filesystem root", 400)
		return
	}
	switch q.Op {
	case "mkdir":
		e = os.Mkdir(p, 0750)
	case "delete":
		e = os.RemoveAll(p)
	case "rename", "move":
		var t string
		t, e = f.resolve(q.Target, true)
		if e == nil {
			e = os.Rename(p, t)
		}
	case "copy":
		var t string
		t, e = f.resolve(q.Target, true)
		if e == nil {
			e = copyPath(p, t)
		}
	default:
		http.Error(w, "unsupported operation", 400)
		return
	}
	if e != nil {
		http.Error(w, e.Error(), 400)
		return
	}
	jsonOut(w, map[string]any{"ok": true})
}
func copyPath(src, dst string) error {
	info, e := os.Stat(src)
	if e != nil {
		return e
	}
	if info.IsDir() {
		return filepath.WalkDir(src, func(p string, d fs.DirEntry, e error) error {
			if e != nil {
				return e
			}
			rel, _ := filepath.Rel(src, p)
			to := filepath.Join(dst, rel)
			if d.IsDir() {
				return os.MkdirAll(to, 0750)
			}
			return copyFile(p, to)
		})
	}
	return copyFile(src, dst)
}
func copyFile(src, dst string) error {
	in, e := os.Open(src)
	if e != nil {
		return e
	}
	defer in.Close()
	info, _ := in.Stat()
	out, e := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode().Perm())
	if e != nil {
		return e
	}
	_, e = io.Copy(out, in)
	ce := out.Close()
	if e == nil {
		e = ce
	}
	return e
}
