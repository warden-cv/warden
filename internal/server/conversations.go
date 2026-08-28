package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

type durableAgentEvent struct {
	Kind      string `json:"kind"`
	Text      string `json:"text"`
	Name      string `json:"name,omitempty"`
	CreatedAt int64  `json:"createdAt,omitempty"`
}

type durableConversation struct {
	ID              string              `json:"id"`
	Title           string              `json:"title"`
	Workspace       string              `json:"workspace"`
	Provider        string              `json:"provider"`
	Model           string              `json:"model,omitempty"`
	OpenCodeSession string              `json:"openCodeSession,omitempty"`
	State           string              `json:"state,omitempty"`
	CreatedAt       int64               `json:"createdAt"`
	UpdatedAt       int64               `json:"updatedAt"`
	ArchivedAt      int64               `json:"archivedAt,omitempty"`
	Events          []durableAgentEvent `json:"events"`
}

func (a *app) conversationsAPI(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.auth.get(r)
	if !ok {
		http.Error(w, "unauthorized", 401)
		return
	}
	switch r.Method {
	case http.MethodGet:
		items, err := a.loadConversations(sess.AccountID)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		jsonOut(w, items)
	case http.MethodPost:
		var q struct {
			Conversations []durableConversation `json:"conversations"`
		}
		if !decodeLargeJSON(w, r, &q) {
			return
		}
		if len(q.Conversations) > 250 {
			http.Error(w, "too many conversations", 400)
			return
		}
		for i := range q.Conversations {
			if err := a.saveConversation(sess.AccountID, &q.Conversations[i]); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
		}
		jsonOut(w, map[string]any{"ok": true, "imported": len(q.Conversations)})
	default:
		http.Error(w, "method", 405)
	}
}

func (a *app) conversationAPI(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.auth.get(r)
	if !ok {
		http.Error(w, "unauthorized", 401)
		return
	}
	switch r.Method {
	case http.MethodPut:
		var q durableConversation
		if !decodeLargeJSON(w, r, &q) {
			return
		}
		if err := a.saveConversation(sess.AccountID, &q); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		jsonOut(w, map[string]bool{"ok": true})
	case http.MethodDelete:
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if !validAgentSessionID(id) {
			http.Error(w, "invalid conversation id", 400)
			return
		}
		if _, err := a.db.Exec("DELETE FROM conversations WHERE account_id=? AND id=?", sess.AccountID, id); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		jsonOut(w, map[string]bool{"ok": true})
	default:
		http.Error(w, "method", 405)
	}
}

func decodeLargeJSON(w http.ResponseWriter, r *http.Request, value any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<20)).Decode(value); err != nil {
		http.Error(w, "invalid json", 400)
		return false
	}
	return true
}

func (a *app) saveConversation(accountID string, c *durableConversation) error {
	if accountID == "" || !validAgentSessionID(c.ID) {
		return errors.New("invalid conversation identity")
	}
	if len(c.Title) > 500 || len(c.Workspace) > 4096 || len(c.Events) > 2000 || len(c.OpenCodeSession) > 256 {
		return errors.New("conversation exceeds storage limits")
	}
	if c.Workspace != "" {
		if _, err := a.files.resolve(c.Workspace, false); err != nil {
			return errors.New("invalid conversation workspace")
		}
	}
	now := time.Now().UnixMilli()
	if c.CreatedAt <= 0 {
		c.CreatedAt = now
	}
	if c.Provider == "" {
		c.Provider = "opencode"
	}
	if c.State == "" {
		c.State = "idle"
	}
	c.UpdatedAt = now
	var archived any
	if c.ArchivedAt > 0 {
		archived = c.ArchivedAt
	}
	tx, err := a.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO conversations(account_id,id,title,workspace,provider,model,opencode_session_id,state,created_at,updated_at,archived_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(account_id,id) DO UPDATE SET title=excluded.title,
		workspace=excluded.workspace,provider=excluded.provider,model=excluded.model,
		opencode_session_id=excluded.opencode_session_id,state=excluded.state,updated_at=excluded.updated_at,archived_at=excluded.archived_at`,
		accountID, c.ID, strings.TrimSpace(c.Title), c.Workspace, c.Provider, c.Model, c.OpenCodeSession, c.State, c.CreatedAt, c.UpdatedAt, archived)
	if err != nil {
		return err
	}
	if _, err = tx.Exec("DELETE FROM conversation_events WHERE account_id=? AND conversation_id=?", accountID, c.ID); err != nil {
		return err
	}
	for sequence, event := range c.Events {
		if event.Kind == "" || len(event.Text) > 1<<20 || len(event.Name) > 500 {
			return errors.New("invalid conversation event")
		}
		created := event.CreatedAt
		if created <= 0 {
			created = c.CreatedAt + int64(sequence)
		}
		if _, err = tx.Exec("INSERT INTO conversation_events(account_id,conversation_id,sequence,kind,text,name,created_at) VALUES(?,?,?,?,?,?,?)", accountID, c.ID, sequence, event.Kind, event.Text, event.Name, created); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (a *app) loadConversations(accountID string) ([]durableConversation, error) {
	rows, err := a.db.Query(`SELECT id,title,workspace,provider,model,opencode_session_id,state,created_at,updated_at,archived_at
		FROM conversations WHERE account_id=? ORDER BY updated_at DESC`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []durableConversation{}
	for rows.Next() {
		var c durableConversation
		var archived sql.NullInt64
		if err := rows.Scan(&c.ID, &c.Title, &c.Workspace, &c.Provider, &c.Model, &c.OpenCodeSession, &c.State, &c.CreatedAt, &c.UpdatedAt, &archived); err != nil {
			return nil, err
		}
		if archived.Valid {
			c.ArchivedAt = archived.Int64
		}
		events, err := a.loadConversationEvents(accountID, c.ID)
		if err != nil {
			return nil, err
		}
		c.Events = events
		items = append(items, c)
	}
	return items, rows.Err()
}

func (a *app) loadConversationEvents(accountID, conversationID string) ([]durableAgentEvent, error) {
	rows, err := a.db.Query("SELECT kind,text,name,created_at FROM conversation_events WHERE account_id=? AND conversation_id=? ORDER BY sequence", accountID, conversationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := []durableAgentEvent{}
	for rows.Next() {
		var event durableAgentEvent
		if err := rows.Scan(&event.Kind, &event.Text, &event.Name, &event.CreatedAt); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (a *app) startDurableAgentRun(id, accountID, conversationID, prompt, workspace, provider, model string) error {
	now := time.Now().UnixMilli()
	tx, err := a.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`INSERT INTO conversations(account_id,id,title,workspace,provider,model,state,created_at,updated_at)
		VALUES(?,?,?,?,?,?,'running',?,?) ON CONFLICT(account_id,id) DO UPDATE SET workspace=excluded.workspace,
		provider=excluded.provider,model=excluded.model,state='running',updated_at=excluded.updated_at`, accountID, conversationID, "", workspace, provider, model, now, now); err != nil {
		return err
	}
	if _, err = tx.Exec("INSERT INTO agent_runs(id,account_id,conversation_id,state,prompt,started_at) VALUES(?,?,?,'running',?,?)", id, accountID, conversationID, prompt, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (a *app) finishDurableAgentRun(id, accountID, conversationID, state, sessionID, message string, input, output uint64, cost float64) {
	now := time.Now().UnixMilli()
	tx, err := a.db.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()
	if _, err = tx.Exec("UPDATE agent_runs SET state=?,finished_at=?,error=?,input_tokens=?,output_tokens=?,estimated_cost_usd=? WHERE id=? AND account_id=?", state, now, message, input, output, cost, id, accountID); err != nil {
		return
	}
	_, err = tx.Exec(`UPDATE conversations SET state=?,opencode_session_id=CASE WHEN ?='' THEN opencode_session_id ELSE ? END,updated_at=? WHERE account_id=? AND id=?`, state, sessionID, sessionID, now, accountID, conversationID)
	if err == nil {
		_ = tx.Commit()
	}
}
