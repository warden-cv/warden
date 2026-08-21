package server

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func (f *fileAPI) archiveDownload(w http.ResponseWriter, r *http.Request) {
	paths := r.URL.Query()["path"]
	if len(paths) == 0 {
		http.Error(w, "no files selected", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="warden-selection.zip"`)
	zw := zip.NewWriter(w)
	for _, rel := range paths {
		p, err := f.resolve(rel, false)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		base := filepath.Base(p)
		if err := addPathToZip(zw, p, base); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	}
	if err := zw.Close(); err != nil {
		return
	}
}

func (f *fileAPI) compress(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", 405)
		return
	}
	var q struct {
		Paths  []string `json:"paths"`
		Target string   `json:"target"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 128<<10)).Decode(&q) != nil || len(q.Paths) == 0 {
		http.Error(w, "invalid request", 400)
		return
	}
	if !strings.HasSuffix(strings.ToLower(q.Target), ".zip") {
		q.Target += ".zip"
	}
	target, err := f.resolve(q.Target, true)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	sources := make([]string, 0, len(q.Paths))
	for _, rel := range q.Paths {
		p, e := f.resolve(rel, false)
		if e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		if p == f.root {
			http.Error(w, "refusing to archive configured root", 400)
			return
		}
		if isWithin(p, target) {
			http.Error(w, "archive target cannot be inside selected directory", 400)
			return
		}
		sources = append(sources, p)
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), ".warden-archive-*.zip")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	zw := zip.NewWriter(tmp)
	for _, p := range sources {
		if err = addPathToZip(zw, p, filepath.Base(p)); err != nil {
			break
		}
	}
	if closeErr := zw.Close(); err == nil {
		err = closeErr
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(tmpName, target)
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	jsonOut(w, map[string]any{"ok": true, "path": q.Target})
}

func (f *fileAPI) extract(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", 405)
		return
	}
	var q struct{ Path, Target string }
	if json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&q) != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	src, err := f.resolve(q.Path, false)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if strings.ToLower(filepath.Ext(src)) != ".zip" {
		http.Error(w, "v1 extraction supports .zip archives", 400)
		return
	}
	targetRel := q.Target
	if targetRel == "" {
		targetRel = filepath.ToSlash(filepath.Join(filepath.Dir(q.Path), strings.TrimSuffix(filepath.Base(q.Path), filepath.Ext(q.Path))))
	}
	target, err := f.resolve(targetRel, true)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if err = os.MkdirAll(target, 0750); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	zr, err := zip.OpenReader(src)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	defer zr.Close()
	if len(zr.File) > 10000 {
		http.Error(w, "archive contains too many entries", 400)
		return
	}
	var total uint64
	for _, zf := range zr.File {
		total += zf.UncompressedSize64
		if total > 2<<30 {
			http.Error(w, "archive expands beyond 2 GiB safety limit", 400)
			return
		}
		if zf.Mode()&os.ModeSymlink != 0 {
			http.Error(w, "symlinks in archives are not extracted", 400)
			return
		}
		clean := filepath.Clean(filepath.FromSlash(zf.Name))
		if clean == "." || filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
			http.Error(w, "archive contains unsafe path", 400)
			return
		}
		out := filepath.Join(target, clean)
		if !isWithin(target, out) {
			http.Error(w, "archive path escapes extraction directory", 400)
			return
		}
		if zf.FileInfo().IsDir() {
			if err = os.MkdirAll(out, 0750); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			continue
		}
		if err = os.MkdirAll(filepath.Dir(out), 0750); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		rc, e := zf.Open()
		if e != nil {
			http.Error(w, e.Error(), 500)
			return
		}
		mode := zf.Mode().Perm()
		if mode == 0 {
			mode = 0640
		}
		of, e := os.OpenFile(out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
		if e == nil {
			_, e = io.Copy(of, rc)
		}
		rc.Close()
		if of != nil {
			if ce := of.Close(); e == nil {
				e = ce
			}
		}
		if e != nil {
			http.Error(w, e.Error(), 500)
			return
		}
	}
	jsonOut(w, map[string]any{"ok": true, "path": targetRel})
}

func addPathToZip(zw *zip.Writer, src, archiveBase string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing to archive symlink")
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		return errors.New("refusing to archive special file")
	}
	if !info.IsDir() {
		return addFileToZip(zw, src, filepath.ToSlash(archiveBase), info)
	}
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		inf, err := d.Info()
		if err != nil {
			return err
		}
		if inf.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to archive symlink %s", p)
		}
		rel, _ := filepath.Rel(src, p)
		name := filepath.ToSlash(filepath.Join(archiveBase, rel))
		if d.IsDir() {
			if rel == "." {
				return nil
			}
			h, _ := zip.FileInfoHeader(inf)
			h.Name = strings.TrimSuffix(name, "/") + "/"
			_, err = zw.CreateHeader(h)
			return err
		}
		return addFileToZip(zw, p, name, inf)
	})
}
func addFileToZip(zw *zip.Writer, src, name string, info fs.FileInfo) error {
	h, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	h.Name = name
	h.Method = zip.Deflate
	dst, err := zw.CreateHeader(h)
	if err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	_, err = io.Copy(dst, in)
	return err
}
func isWithin(root, child string) bool {
	rel, err := filepath.Rel(root, child)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}
