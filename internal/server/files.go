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
	"sync"

	coreeditor "github.com/gantry-tools/gantry-core/editor"
	coreworkspace "github.com/gantry-tools/gantry-core/workspace"
)

type fileAPI struct {
	root           string
	resolver       *coreworkspace.Resolver
	workspaceMu    sync.Mutex
	workspaceUndos map[string]*workspaceUndo
}
type fileEntry struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Dir      bool   `json:"dir"`
	Size     int64  `json:"size"`
	Mode     string `json:"mode"`
	Modified int64  `json:"modified"`
}

func (f *fileAPI) startPath(home string) string {
	if home == "" {
		return "/"
	}
	abs, err := filepath.Abs(home)
	if err != nil {
		return "/"
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "/"
	}
	rel, err := filepath.Rel(f.root, real)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "/"
	}
	if rel == "." {
		return "/"
	}
	return "/" + filepath.ToSlash(rel)
}
func (f *fileAPI) shellStart(home string) string {
	start := f.startPath(home)
	if start == "/" {
		return f.root
	}
	return filepath.Join(f.root, filepath.FromSlash(strings.TrimPrefix(start, "/")))
}
func (f *fileAPI) virtualRootLabel() string { return f.root }

func newFiles(root string) (*fileAPI, error) {
	resolver, e := coreworkspace.New(root)
	if e != nil {
		return nil, e
	}
	return &fileAPI{root: resolver.Root(), resolver: resolver, workspaceUndos: make(map[string]*workspaceUndo)}, nil
}
func (f *fileAPI) resolve(rel string, allowMissing bool) (string, error) {
	virtual := strings.TrimPrefix(filepath.Clean("/"+rel), "/")
	var resolved string
	var e error
	if allowMissing {
		resolved, e = f.resolver.ResolveForCreate(virtual)
	} else {
		resolved, e = f.resolver.Resolve(virtual)
	}
	return resolved, e
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
	if r.URL.Query().Get("raw") == "1" {
		w.Header().Set("Content-Disposition", "inline")
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
	if info, statErr := os.Stat(p); statErr == nil {
		mode = info.Mode().Perm()
	}
	e = writeAtomicPath(p, body, mode)
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
		if e == nil && p != t {
			if _, statErr := os.Lstat(t); statErr == nil {
				e = errors.New("target already exists")
			} else if !errors.Is(statErr, os.ErrNotExist) {
				e = statErr
			} else {
				e = os.Rename(p, t)
			}
		}
	case "copy":
		var t string
		t, e = f.resolve(q.Target, true)
		if e == nil {
			if _, statErr := os.Lstat(t); statErr == nil {
				e = errors.New("target already exists")
			} else if !errors.Is(statErr, os.ErrNotExist) {
				e = statErr
			} else {
				e = copyPath(p, t)
			}
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
	info, e := os.Lstat(src)
	if e != nil {
		return e
	}
	if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
		return errors.New("refusing to copy symlink or special file")
	}
	if info.IsDir() {
		return filepath.WalkDir(src, func(p string, d fs.DirEntry, e error) error {
			if e != nil {
				return e
			}
			info, e := d.Info()
			if e != nil {
				return e
			}
			if info.Mode()&os.ModeSymlink != 0 || (!d.IsDir() && !info.Mode().IsRegular()) {
				return errors.New("refusing to copy symlink or special file")
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
	info, e := os.Lstat(src)
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() {
		return errors.New("refusing to copy non-regular file")
	}
	in, e := os.Open(src)
	if e != nil {
		return e
	}
	defer in.Close()
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

func writeAtomicPath(p string, body []byte, mode fs.FileMode) error {
	return coreeditor.WriteAtomicMode(p, body, mode)
}
