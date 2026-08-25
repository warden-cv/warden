package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

type alertRule struct {
	ID              string  `json:"id"`
	Name            string  `json:"name"`
	Metric          string  `json:"metric"`
	Operator        string  `json:"operator"`
	Threshold       float64 `json:"threshold"`
	DurationSeconds int64   `json:"durationSeconds"`
	Severity        string  `json:"severity"`
	Enabled         bool    `json:"enabled"`
	CreatedBy       string  `json:"createdBy,omitempty"`
	CreatedAt       int64   `json:"createdAt,omitempty"`
	UpdatedAt       int64   `json:"updatedAt,omitempty"`
}

type alertInstance struct {
	ID           string  `json:"id"`
	RuleID       string  `json:"ruleId"`
	RuleName     string  `json:"ruleName"`
	Severity     string  `json:"severity"`
	State        string  `json:"state"`
	Value        float64 `json:"value"`
	StartedAt    int64   `json:"startedAt"`
	ResolvedAt   int64   `json:"resolvedAt,omitempty"`
	Acknowledged bool    `json:"acknowledged"`
}

func (a *app) alertsAPI(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.auth.get(r)
	if !ok {
		http.Error(w, "unauthorized", 401)
		return
	}
	switch r.Method {
	case http.MethodGet:
		rules, instances, err := a.loadAlerts(sess.AccountID)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		jsonOut(w, map[string]any{"rules": rules, "instances": instances, "canManage": a.accounts.hasCapability(sess.AccountID, "system.manage")})
	case http.MethodPost:
		var q struct {
			Action     string    `json:"action"`
			Rule       alertRule `json:"rule"`
			ID         string    `json:"id"`
			InstanceID string    `json:"instanceId"`
			Note       string    `json:"note"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&q) != nil {
			http.Error(w, "invalid json", 400)
			return
		}
		var err error
		switch q.Action {
		case "save":
			if !a.accounts.hasCapability(sess.AccountID, "system.manage") {
				http.Error(w, "forbidden", 403)
				return
			}
			err = a.saveAlertRule(sess.AccountID, &q.Rule)
		case "delete":
			if !a.accounts.hasCapability(sess.AccountID, "system.manage") {
				http.Error(w, "forbidden", 403)
				return
			}
			_, err = a.db.Exec("DELETE FROM alert_rules WHERE id=?", q.ID)
		case "acknowledge":
			_, err = a.db.Exec(`INSERT INTO alert_acknowledgements(instance_id,account_id,note,created_at) VALUES(?,?,?,?)
				ON CONFLICT(instance_id,account_id) DO UPDATE SET note=excluded.note,created_at=excluded.created_at`, q.InstanceID, sess.AccountID, strings.TrimSpace(q.Note), time.Now().UnixMilli())
		default:
			err = errors.New("unknown alert action")
		}
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		jsonOut(w, map[string]bool{"ok": true})
	default:
		http.Error(w, "method", 405)
	}
}

func (a *app) saveAlertRule(accountID string, rule *alertRule) error {
	validMetric := map[string]bool{"cpu": true, "memory": true, "disk": true, "load1": true}
	if !validMetric[rule.Metric] || (rule.Operator != ">" && rule.Operator != "<") || rule.Threshold < 0 || rule.DurationSeconds < 0 || rule.DurationSeconds > 86400 || len(rule.Name) > 200 {
		return errors.New("invalid alert rule")
	}
	if rule.ID == "" {
		rule.ID = token(18)
	}
	if !validAgentSessionID(rule.ID) {
		return errors.New("invalid alert rule id")
	}
	if strings.TrimSpace(rule.Name) == "" {
		rule.Name = rule.Metric + " threshold"
	}
	if rule.Severity != "critical" && rule.Severity != "info" {
		rule.Severity = "warning"
	}
	now := time.Now().UnixMilli()
	_, err := a.db.Exec(`INSERT INTO alert_rules(id,name,metric,operator,threshold,duration_seconds,severity,enabled,created_by,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,metric=excluded.metric,
		operator=excluded.operator,threshold=excluded.threshold,duration_seconds=excluded.duration_seconds,severity=excluded.severity,enabled=excluded.enabled,updated_at=excluded.updated_at`,
		rule.ID, strings.TrimSpace(rule.Name), rule.Metric, rule.Operator, rule.Threshold, rule.DurationSeconds, rule.Severity, rule.Enabled, accountID, now, now)
	return err
}

func (a *app) loadAlerts(accountID string) ([]alertRule, []alertInstance, error) {
	rules := []alertRule{}
	rows, err := a.db.Query("SELECT id,name,metric,operator,threshold,duration_seconds,severity,enabled,created_by,created_at,updated_at FROM alert_rules ORDER BY created_at")
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var rule alertRule
		if err := rows.Scan(&rule.ID, &rule.Name, &rule.Metric, &rule.Operator, &rule.Threshold, &rule.DurationSeconds, &rule.Severity, &rule.Enabled, &rule.CreatedBy, &rule.CreatedAt, &rule.UpdatedAt); err != nil {
			rows.Close()
			return nil, nil, err
		}
		rules = append(rules, rule)
	}
	rows.Close()
	instances := []alertInstance{}
	rows, err = a.db.Query(`SELECT i.id,i.rule_id,r.name,r.severity,i.state,i.value,i.started_at,i.resolved_at,
		EXISTS(SELECT 1 FROM alert_acknowledgements a WHERE a.instance_id=i.id AND a.account_id=?)
		FROM alert_instances i JOIN alert_rules r ON r.id=i.rule_id ORDER BY i.started_at DESC LIMIT 100`, accountID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var item alertInstance
		var resolved sql.NullInt64
		if err := rows.Scan(&item.ID, &item.RuleID, &item.RuleName, &item.Severity, &item.State, &item.Value, &item.StartedAt, &resolved, &item.Acknowledged); err != nil {
			return nil, nil, err
		}
		if resolved.Valid {
			item.ResolvedAt = resolved.Int64
		}
		instances = append(instances, item)
	}
	return rules, instances, rows.Err()
}

func (a *app) runAlertEvaluator(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.evaluateAlerts(monitor(a.files.root), time.Now())
		}
	}
}

func (a *app) evaluateAlerts(snapshot monitorSnapshot, now time.Time) {
	rows, err := a.db.Query("SELECT id,metric,operator,threshold,duration_seconds FROM alert_rules WHERE enabled=1")
	if err != nil {
		return
	}
	type candidate struct {
		id, metric, operator string
		threshold            float64
		duration             int64
	}
	items := []candidate{}
	for rows.Next() {
		var c candidate
		if rows.Scan(&c.id, &c.metric, &c.operator, &c.threshold, &c.duration) == nil {
			items = append(items, c)
		}
	}
	rows.Close()
	for _, rule := range items {
		value := alertMetricValue(snapshot, rule.metric)
		breached := rule.operator == ">" && value > rule.threshold || rule.operator == "<" && value < rule.threshold
		var breachSince int64
		breachErr := a.db.QueryRow("SELECT breach_since FROM alert_rule_evaluation WHERE rule_id=?", rule.id).Scan(&breachSince)
		if breached && breachErr == sql.ErrNoRows {
			breachSince = now.UnixMilli()
			_, _ = a.db.Exec("INSERT INTO alert_rule_evaluation(rule_id,breach_since,last_value) VALUES(?,?,?)", rule.id, breachSince, value)
		} else if breached {
			_, _ = a.db.Exec("UPDATE alert_rule_evaluation SET last_value=? WHERE rule_id=?", value, rule.id)
		} else {
			_, _ = a.db.Exec("DELETE FROM alert_rule_evaluation WHERE rule_id=?", rule.id)
		}
		var id string
		var started int64
		err := a.db.QueryRow("SELECT id,started_at FROM alert_instances WHERE rule_id=? AND state='firing'", rule.id).Scan(&id, &started)
		ready := breached && now.UnixMilli()-breachSince >= rule.duration*1000
		if ready && err == sql.ErrNoRows {
			id = token(18)
			started = now.UnixMilli()
			_, _ = a.db.Exec("INSERT INTO alert_instances(id,rule_id,state,value,started_at) VALUES(?,?,'firing',?,?)", id, rule.id, value, started)
			_, _ = a.db.Exec("INSERT INTO alert_events(rule_id,instance_id,kind,value,created_at) VALUES(?,?, 'firing',?,?)", rule.id, id, value, started)
		} else if ready && err == nil {
			_, _ = a.db.Exec("UPDATE alert_instances SET value=? WHERE id=?", value, id)
		} else if !breached && err == nil {
			at := now.UnixMilli()
			_, _ = a.db.Exec("UPDATE alert_instances SET state='resolved',value=?,resolved_at=? WHERE id=?", value, at, id)
			_, _ = a.db.Exec("INSERT INTO alert_events(rule_id,instance_id,kind,value,created_at) VALUES(?,?, 'resolved',?,?)", rule.id, id, value, at)
		}
	}
}

func alertMetricValue(s monitorSnapshot, metric string) float64 {
	switch metric {
	case "cpu":
		return s.CPU
	case "memory":
		if s.Memory.Total > 0 {
			return 100 * float64(s.Memory.Used) / float64(s.Memory.Total)
		}
	case "disk":
		if s.Disk.Total > 0 {
			return 100 * float64(s.Disk.Used) / float64(s.Disk.Total)
		}
	case "load1":
		return s.Load[0]
	}
	return 0
}
