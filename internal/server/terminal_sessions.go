package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	coreterminal "github.com/gantry-tools/gantry-core/terminal"
)

type terminalSession = coreterminal.Session

const maxTerminalSessionsPerAccount = coreterminal.DefaultSessionLimit

func (a *app) ensureTerminalSessionCapacity(accountID, id string) error {
	var exists, count int
	if err := a.db.QueryRow("SELECT EXISTS(SELECT 1 FROM terminal_sessions WHERE account_id=? AND id=?), COUNT(*) FROM terminal_sessions WHERE account_id=?", accountID, id, accountID).Scan(&exists, &count); err != nil {
		return err
	}
	return coreterminal.CheckCapacity(exists != 0, count, maxTerminalSessionsPerAccount)
}

func (a *app) terminalSessionsAPI(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.auth.get(r)
	if !ok {
		http.Error(w, "unauthorized", 401)
		return
	}
	switch r.Method {
	case http.MethodGet:
		items, err := a.loadTerminalSessions(sess.AccountID)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		jsonOut(w, items)
	case http.MethodPut:
		var q terminalSession
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&q) != nil {
			http.Error(w, "invalid json", 400)
			return
		}
		if err := a.saveTerminalSession(sess.AccountID, &q); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		jsonOut(w, map[string]bool{"ok": true})
	case http.MethodDelete:
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if !validAgentSessionID(id) {
			http.Error(w, "invalid terminal session", 400)
			return
		}
		_, err := a.db.Exec("DELETE FROM terminal_sessions WHERE account_id=? AND id=?", sess.AccountID, id)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		jsonOut(w, map[string]bool{"ok": true})
	default:
		http.Error(w, "method", 405)
	}
}

func (a *app) saveTerminalSession(accountID string, s *terminalSession) error {
	normalized, normalizeErr := coreterminal.Normalize(*s)
	if accountID == "" || normalizeErr != nil {
		return errors.New("invalid terminal session")
	}
	*s = normalized
	_, err := a.files.resolve(s.CWD, false)
	if err != nil {
		return errors.New("invalid terminal cwd")
	}
	if err := a.ensureTerminalSessionCapacity(accountID, s.ID); err != nil {
		return err
	}
	now := time.Now().UnixMilli()
	if s.CreatedAt <= 0 {
		s.CreatedAt = now
	}
	var closed any
	if s.ClosedAt > 0 {
		closed = s.ClosedAt
	}
	_, err = a.db.Exec(`INSERT INTO terminal_sessions(account_id,id,title,cwd,state,created_at,updated_at,closed_at)
		VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(account_id,id) DO UPDATE SET title=excluded.title,cwd=excluded.cwd,
		state=excluded.state,updated_at=excluded.updated_at,closed_at=excluded.closed_at`, accountID, s.ID, s.Title, s.CWD, s.State, s.CreatedAt, now, closed)
	return err
}

func (a *app) loadTerminalSessions(accountID string) ([]terminalSession, error) {
	rows, err := a.db.Query(`SELECT s.id,s.title,s.cwd,s.state,s.created_at,s.updated_at,s.closed_at,COALESCE(b.output,X'')
		FROM terminal_sessions s LEFT JOIN terminal_scrollback b ON b.account_id=s.account_id AND b.session_id=s.id
		WHERE s.account_id=? ORDER BY s.updated_at DESC`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []terminalSession{}
	for rows.Next() {
		var item terminalSession
		var closed sql.NullInt64
		var output []byte
		if err := rows.Scan(&item.ID, &item.Title, &item.CWD, &item.State, &item.CreatedAt, &item.UpdatedAt, &closed, &output); err != nil {
			return nil, err
		}
		if closed.Valid {
			item.ClosedAt = closed.Int64
		}
		item.Scrollback = string(output)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (a *app) connectTerminalSession(accountID, id, cwd string) error {
	if err := a.ensureTerminalSessionCapacity(accountID, id); err != nil {
		return err
	}
	now := time.Now().UnixMilli()
	_, err := a.db.Exec(`INSERT INTO terminal_sessions(account_id,id,title,cwd,state,created_at,updated_at)
		VALUES(?,?, 'Terminal',?,'connected',?,?) ON CONFLICT(account_id,id) DO UPDATE SET cwd=excluded.cwd,state='connected',updated_at=excluded.updated_at,closed_at=NULL`, accountID, id, cwd, now, now)
	return err
}

func (a *app) disconnectTerminalSession(accountID, id string) {
	_, _ = a.db.Exec("UPDATE terminal_sessions SET state='disconnected',updated_at=? WHERE account_id=? AND id=?", time.Now().UnixMilli(), accountID, id)
}

func (a *app) appendTerminalScrollback(accountID, id string, p []byte) {
	if len(p) == 0 {
		return
	}
	// PTY output is byte-oriented; invalid UTF-8 is safely normalized for the browser.
	p = coreterminal.NormalizeOutput(p)
	_, _ = a.db.Exec(`INSERT INTO terminal_scrollback(account_id,session_id,output,updated_at) VALUES(?,?,?,?)
		ON CONFLICT(account_id,session_id) DO UPDATE SET output=substr(output || excluded.output,-262144),updated_at=excluded.updated_at`, accountID, id, p, time.Now().UnixMilli())
}
