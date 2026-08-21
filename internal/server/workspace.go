package server

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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
	changed, replacements := 0, 0
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
		if e = writeAtomicPath(p, []byte(next), info.Mode().Perm()); e != nil {
			return e
		}
		changed++
		replacements += n
		return nil
	})
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	jsonOut(w, map[string]any{"ok": true, "files": changed, "replacements": replacements})
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
		sc := bufio.NewScanner(strings.NewReader(string(b)))
		sc.Buffer(make([]byte, 64<<10), 2<<20)
		line := 0
		for sc.Scan() {
			line++
			txt := sc.Text()
			locs := re.FindAllStringIndex(txt, -1)
			for _, loc := range locs {
				rel, _ := filepath.Rel(f.root, p)
				preview := strings.TrimSpace(txt)
				if len(preview) > 180 {
					preview = preview[:180] + "…"
				}
				out = append(out, workspaceMatch{Path: "/" + filepath.ToSlash(rel), Line: line, Column: loc[0] + 1, Preview: preview})
				if len(out) >= limit {
					return filepath.SkipAll
				}
			}
		}
		return nil
	})
	return out, err
}
func compileWorkspacePattern(q workspaceQuery) (*regexp.Regexp, error) {
	pat := q.Query
	if !q.Regex {
		pat = regexp.QuoteMeta(pat)
	}
	if !q.CaseSensitive {
		pat = "(?i)" + pat
	}
	return regexp.Compile(pat)
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
