package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type sourceControlEntry struct {
	Path      string `json:"path"`
	Index     string `json:"index"`
	Worktree  string `json:"worktree"`
	Staged    bool   `json:"staged"`
	Changed   bool   `json:"changed"`
	Untracked bool   `json:"untracked"`
}

type sourceControlStatus struct {
	Repository bool                 `json:"repository"`
	Branch     string               `json:"branch,omitempty"`
	Entries    []sourceControlEntry `json:"entries"`
}

func (f *fileAPI) sourceControlStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	root, err := f.gitWorkspaceRoot(r.URL.Query().Get("root"))
	if errors.Is(err, errNotGitWorkspace) {
		jsonOut(w, sourceControlStatus{Repository: false, Entries: []sourceControlEntry{}})
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	branch, _ := runGit(root, "branch", "--show-current")
	raw, err := runGitBytes(root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	entries := parseGitStatus(raw)
	jsonOut(w, sourceControlStatus{Repository: true, Branch: strings.TrimSpace(branch), Entries: entries})
}

var errNotGitWorkspace = errors.New("workspace is not a Git repository root")

func (f *fileAPI) gitWorkspaceRoot(virtual string) (string, error) {
	if strings.TrimSpace(virtual) == "" {
		return "", errors.New("workspace is required")
	}
	root, err := f.resolve(virtual, false)
	if err != nil {
		return "", err
	}
	out, err := runGit(root, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", errNotGitWorkspace
	}
	gitRoot, err := filepath.EvalSymlinks(strings.TrimSpace(out))
	if err != nil {
		return "", errNotGitWorkspace
	}
	if filepath.Clean(gitRoot) != filepath.Clean(root) {
		return "", errNotGitWorkspace
	}
	return root, nil
}

func parseGitStatus(raw []byte) []sourceControlEntry {
	parts := strings.Split(string(raw), "\x00")
	out := make([]sourceControlEntry, 0, len(parts))
	for i := 0; i < len(parts); i++ {
		item := parts[i]
		if len(item) < 4 {
			continue
		}
		index, worktree := item[:1], item[1:2]
		path := item[3:]
		if (index == "R" || index == "C" || worktree == "R" || worktree == "C") && i+1 < len(parts) && parts[i+1] != "" {
			i++ // porcelain -z includes the other rename/copy path next
		}
		out = append(out, sourceControlEntry{
			Path: path, Index: index, Worktree: worktree,
			Staged:    index != " " && index != "?",
			Changed:   worktree != " " || index == "?",
			Untracked: index == "?" && worktree == "?",
		})
	}
	return out
}

func (f *fileAPI) sourceControlMutate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var q struct {
		Root, Action, Path, Message string
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&q) != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	root, err := f.gitWorkspaceRoot(q.Root)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rel := filepath.Clean(filepath.FromSlash(q.Path))
	if rel == "." || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		if q.Action == "stage" || q.Action == "unstage" {
			http.Error(w, "invalid Git path", http.StatusBadRequest)
			return
		}
	}
	switch q.Action {
	case "stage":
		_, err = runGit(root, "add", "--", rel)
	case "unstage":
		_, err = runGit(root, "reset", "--quiet", "--", rel)
	case "stage-all":
		_, err = runGit(root, "add", "-A", "--", ".")
	case "unstage-all":
		_, err = runGit(root, "reset", "--quiet")
	case "commit":
		message := strings.TrimSpace(q.Message)
		if message == "" || len(message) > 1000 || strings.ContainsRune(message, '\x00') {
			http.Error(w, "commit message must be 1-1000 characters", http.StatusBadRequest)
			return
		}
		_, err = runGit(root, "commit", "-m", message)
	default:
		http.Error(w, "unsupported source-control action", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonOut(w, map[string]any{"ok": true})
}

func gitHasHead(root string) bool {
	_, err := runGit(root, "rev-parse", "--verify", "HEAD")
	return err == nil
}

func runGit(root string, args ...string) (string, error) {
	b, err := runGitBytes(root, args...)
	return string(b), err
}

func runGitBytes(root string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", root}, args...)...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return nil, errors.New("git command timed out")
	}
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return nil, errors.New(msg)
	}
	return out, nil
}
