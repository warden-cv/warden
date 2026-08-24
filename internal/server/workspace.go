package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type workspaceMatch struct {
	Path    string `json:"path"`
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Preview string `json:"preview"`
}
type workspaceQuery struct {
	Root, Query, Replacement string
	Regex, CaseSensitive     bool
}
type workspaceUndoFile struct {
	path, virtual string
	before        []byte
	afterHash     [32]byte
	mode          os.FileMode
}
type workspaceUndo struct {
	created time.Time
	files   []workspaceUndoFile
}
type workspaceChange struct {
	physical, virtual string
	before, after     []byte
	mode              os.FileMode
	replacements      int
}

func (f *fileAPI) workspaceSearch(w http.ResponseWriter, r *http.Request) {
	q := workspaceQuery{Root: r.URL.Query().Get("root"), Query: r.URL.Query().Get("q"), Regex: r.URL.Query().Get("regex") == "1", CaseSensitive: r.URL.Query().Get("case") == "1"}
	if q.Query == "" {
		jsonOut(w, []workspaceMatch{})
		return
	}
	matches, err := f.searchWorkspace(q, 500)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	jsonOut(w, matches)
}

func (f *fileAPI) workspaceReplace(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", 405)
		return
	}
	var q workspaceQuery
	if json.NewDecoder(io.LimitReader(r.Body, 128<<10)).Decode(&q) != nil || q.Query == "" {
		http.Error(w, "invalid request", 400)
		return
	}
	root, err := f.resolve(q.Root, false)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	re, err := compileWorkspacePattern(q)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	changes := make([]workspaceChange, 0)
	replacements, backupBytes := 0, int64(0)
	const maxUndoBytes = int64(32 << 20)
	err = filepath.WalkDir(root, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" && p != root {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, e := d.Info()
		if e != nil || !info.Mode().IsRegular() || info.Size() > 2<<20 {
			return nil
		}
		b, e := os.ReadFile(p)
		if e != nil || looksBinary(b) {
			return nil
		}
		old := string(b)
		n := -1
		var next string
		if q.Regex {
			idx := re.FindAllStringIndex(old, -1)
			n = len(idx)
			next = re.ReplaceAllString(old, q.Replacement)
		} else if q.CaseSensitive {
			n = strings.Count(old, q.Query)
			next = strings.ReplaceAll(old, q.Query, q.Replacement)
		} else {
			idx := re.FindAllStringIndex(old, -1)
			n = len(idx)
			next = re.ReplaceAllStringFunc(old, func(string) string { return q.Replacement })
		}
		if n <= 0 {
			return nil
		}
		backupBytes += int64(len(b))
		if backupBytes > maxUndoBytes {
			return errWorkspaceUndoTooLarge
		}
		rel, relErr := filepath.Rel(f.root, p)
		if relErr != nil {
			return relErr
		}
		changes = append(changes, workspaceChange{physical: p, virtual: "/" + filepath.ToSlash(rel), before: append([]byte(nil), b...), after: []byte(next), mode: info.Mode().Perm(), replacements: n})
		replacements += n
		return nil
	})
	if err == errWorkspaceUndoTooLarge {
		http.Error(w, "replace all is too large for safe undo (32 MiB limit)", http.StatusRequestEntityTooLarge)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if len(changes) == 0 {
		jsonOut(w, map[string]any{"ok": true, "files": 0, "replacements": 0, "paths": []string{}})
		return
	}

	token, err := newWorkspaceUndoToken()
	if err != nil {
		http.Error(w, "could not create replace-all undo transaction", 500)
		return
	}
	written := 0
	for i, c := range changes {
		if err = writeAtomicPath(c.physical, c.after, c.mode.Perm()); err != nil {
			for j := written - 1; j >= 0; j-- {
				_ = writeAtomicPath(changes[j].physical, changes[j].before, changes[j].mode.Perm())
			}
			http.Error(w, err.Error(), 500)
			return
		}
		written = i + 1
	}
	undo := &workspaceUndo{created: time.Now(), files: make([]workspaceUndoFile, 0, len(changes))}
	paths := make([]string, 0, len(changes))
	for _, c := range changes {
		undo.files = append(undo.files, workspaceUndoFile{path: c.physical, virtual: c.virtual, before: c.before, afterHash: sha256.Sum256(c.after), mode: c.mode})
		paths = append(paths, c.virtual)
	}
	f.workspaceMu.Lock()
	f.pruneWorkspaceUndosLocked()
	f.workspaceUndos[token] = undo
	f.workspaceMu.Unlock()
	jsonOut(w, map[string]any{"ok": true, "files": len(changes), "replacements": replacements, "paths": paths, "undoToken": token})
}

var errWorkspaceUndoTooLarge = &workspaceUndoLimitError{}

type workspaceUndoLimitError struct{}

func (*workspaceUndoLimitError) Error() string { return "workspace replace undo limit exceeded" }

func newWorkspaceUndoToken() (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	return hex.EncodeToString(b[:]), nil
}
func (f *fileAPI) pruneWorkspaceUndosLocked() {
	cutoff := time.Now().Add(-15 * time.Minute)
	for k, v := range f.workspaceUndos {
		if v.created.Before(cutoff) {
			delete(f.workspaceUndos, k)
		}
	}
	if len(f.workspaceUndos) < 8 {
		return
	}
	var oldest string
	var t time.Time
	for k, v := range f.workspaceUndos {
		if oldest == "" || v.created.Before(t) {
			oldest = k
			t = v.created
		}
	}
	delete(f.workspaceUndos, oldest)
}
func (f *fileAPI) workspaceUndoReplace(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", 405)
		return
	}
	var q struct {
		Token string `json:"token"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&q) != nil || q.Token == "" {
		http.Error(w, "invalid request", 400)
		return
	}
	f.workspaceMu.Lock()
	undo := f.workspaceUndos[q.Token]
	f.workspaceMu.Unlock()
	if undo == nil {
		http.Error(w, "replace-all undo is no longer available", 409)
		return
	}
	for _, u := range undo.files {
		b, e := os.ReadFile(u.path)
		if e != nil || sha256.Sum256(b) != u.afterHash {
			http.Error(w, "cannot undo replace all because a changed file was modified again", 409)
			return
		}
	}
	restored := 0
	for i, u := range undo.files {
		if e := writeAtomicPath(u.path, u.before, u.mode.Perm()); e != nil {
			http.Error(w, e.Error(), 500)
			return
		}
		restored = i + 1
	}
	f.workspaceMu.Lock()
	delete(f.workspaceUndos, q.Token)
	f.workspaceMu.Unlock()
	paths := make([]string, 0, len(undo.files))
	for _, u := range undo.files {
		paths = append(paths, u.virtual)
	}
	jsonOut(w, map[string]any{"ok": true, "files": restored, "paths": paths})
}

func (f *fileAPI) searchWorkspace(q workspaceQuery, limit int) ([]workspaceMatch, error) {
	root, err := f.resolve(q.Root, false)
	if err != nil {
		return nil, err
	}
	re, err := compileWorkspacePattern(q)
	if err != nil {
		return nil, err
	}
	out := make([]workspaceMatch, 0)
	err = filepath.WalkDir(root, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" && p != root {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, e := d.Info()
		if e != nil || !info.Mode().IsRegular() || info.Size() > 2<<20 {
			return nil
		}
		b, e := os.ReadFile(p)
		if e != nil || looksBinary(b) {
			return nil
		}
		text := string(b)
		lines := strings.Split(text, "\n")
		offset := 0
		for i, line := range lines {
			idx := re.FindAllStringIndex(line, -1)
			for _, loc := range idx {
				rel, relErr := filepath.Rel(f.root, p)
				if relErr != nil {
					continue
				}
				preview := strings.TrimSpace(line)
				if len(preview) > 220 {
					preview = preview[:220]
				}
				out = append(out, workspaceMatch{Path: "/" + filepath.ToSlash(rel), Line: i + 1, Column: loc[0] + 1, Preview: preview})
				if len(out) >= limit {
					return io.EOF
				}
			}
			offset += len(line) + 1
			_ = offset
		}
		return nil
	})
	if err == io.EOF {
		err = nil
	}
	return out, err
}
func compileWorkspacePattern(q workspaceQuery) (*regexp.Regexp, error) {
	pattern := q.Query
	if !q.Regex {
		pattern = regexp.QuoteMeta(pattern)
	}
	if !q.CaseSensitive {
		pattern = "(?i)" + pattern
	}
	return regexp.Compile(pattern)
}
func looksBinary(b []byte) bool {
	n := len(b)
	if n > 8192 {
		n = 8192
	}
	for _, c := range b[:n] {
		if c == 0 {
			return true
		}
	}
	return false
}
