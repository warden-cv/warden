package server

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type databaseMigration struct {
	version int
	name    string
	sql     string
}

var databaseMigrations = []databaseMigration{
	{
		version: 1,
		name:    "sqlite foundation",
		sql: `CREATE TABLE application_metadata (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at INTEGER NOT NULL
		);`,
	},
	{
		version: 2,
		name:    "durable agent conversations",
		sql: `CREATE TABLE conversations (
			account_id TEXT NOT NULL,
			id TEXT NOT NULL,
			title TEXT NOT NULL DEFAULT '',
			workspace TEXT NOT NULL DEFAULT '',
			provider TEXT NOT NULL DEFAULT 'opencode',
			model TEXT NOT NULL DEFAULT '',
			opencode_session_id TEXT NOT NULL DEFAULT '',
			state TEXT NOT NULL DEFAULT 'idle',
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			archived_at INTEGER,
			PRIMARY KEY(account_id,id)
		);
		CREATE INDEX conversations_account_updated_idx ON conversations(account_id,archived_at,updated_at DESC);
		CREATE TABLE conversation_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			account_id TEXT NOT NULL,
			conversation_id TEXT NOT NULL,
			sequence INTEGER NOT NULL,
			kind TEXT NOT NULL,
			text TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			UNIQUE(account_id,conversation_id,sequence),
			FOREIGN KEY(account_id,conversation_id) REFERENCES conversations(account_id,id) ON DELETE CASCADE
		);
		CREATE TABLE agent_runs (
			id TEXT PRIMARY KEY,
			account_id TEXT NOT NULL,
			conversation_id TEXT NOT NULL,
			state TEXT NOT NULL,
			prompt TEXT NOT NULL,
			started_at INTEGER NOT NULL,
			finished_at INTEGER,
			error TEXT NOT NULL DEFAULT '',
			input_tokens INTEGER NOT NULL DEFAULT 0,
			output_tokens INTEGER NOT NULL DEFAULT 0,
			estimated_cost_usd REAL NOT NULL DEFAULT 0,
			FOREIGN KEY(account_id,conversation_id) REFERENCES conversations(account_id,id) ON DELETE CASCADE
		);
		CREATE INDEX agent_runs_account_conversation_idx ON agent_runs(account_id,conversation_id,started_at DESC);`,
	},
	{
		version: 3,
		name:    "durable terminal sessions",
		sql: `CREATE TABLE terminal_sessions (
			account_id TEXT NOT NULL,
			id TEXT NOT NULL,
			title TEXT NOT NULL DEFAULT 'Terminal',
			cwd TEXT NOT NULL,
			state TEXT NOT NULL DEFAULT 'disconnected',
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			closed_at INTEGER,
			PRIMARY KEY(account_id,id)
		);
		CREATE INDEX terminal_sessions_account_updated_idx ON terminal_sessions(account_id,closed_at,updated_at DESC);
		CREATE TABLE terminal_scrollback (
			account_id TEXT NOT NULL,
			session_id TEXT NOT NULL,
			output BLOB NOT NULL DEFAULT X'',
			updated_at INTEGER NOT NULL,
			PRIMARY KEY(account_id,session_id),
			FOREIGN KEY(account_id,session_id) REFERENCES terminal_sessions(account_id,id) ON DELETE CASCADE
		);`,
	},
	{
		version: 4,
		name:    "alerts and event rules",
		sql: `CREATE TABLE alert_rules (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			metric TEXT NOT NULL,
			operator TEXT NOT NULL,
			threshold REAL NOT NULL,
			duration_seconds INTEGER NOT NULL DEFAULT 0,
			severity TEXT NOT NULL DEFAULT 'warning',
			enabled INTEGER NOT NULL DEFAULT 1,
			created_by TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		);
		CREATE TABLE alert_instances (
			id TEXT PRIMARY KEY,
			rule_id TEXT NOT NULL,
			state TEXT NOT NULL,
			value REAL NOT NULL,
			started_at INTEGER NOT NULL,
			resolved_at INTEGER,
			FOREIGN KEY(rule_id) REFERENCES alert_rules(id) ON DELETE CASCADE
		);
		CREATE UNIQUE INDEX alert_one_active_instance_idx ON alert_instances(rule_id) WHERE state='firing';
		CREATE TABLE alert_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			rule_id TEXT NOT NULL,
			instance_id TEXT NOT NULL,
			kind TEXT NOT NULL,
			value REAL NOT NULL,
			created_at INTEGER NOT NULL,
			FOREIGN KEY(rule_id) REFERENCES alert_rules(id) ON DELETE CASCADE,
			FOREIGN KEY(instance_id) REFERENCES alert_instances(id) ON DELETE CASCADE
		);
		CREATE TABLE alert_acknowledgements (
			instance_id TEXT NOT NULL,
			account_id TEXT NOT NULL,
			note TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			PRIMARY KEY(instance_id,account_id),
			FOREIGN KEY(instance_id) REFERENCES alert_instances(id) ON DELETE CASCADE
		);
		CREATE TABLE alert_rule_evaluation (
			rule_id TEXT PRIMARY KEY,
			breach_since INTEGER NOT NULL,
			last_value REAL NOT NULL,
			FOREIGN KEY(rule_id) REFERENCES alert_rules(id) ON DELETE CASCADE
		);`,
	},
	{
		version: 5,
		name:    "website revisions and operation jobs",
		sql: `CREATE TABLE websites (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			kind TEXT NOT NULL,
			document_root TEXT NOT NULL DEFAULT '',
			upstream TEXT NOT NULL DEFAULT '',
			enabled INTEGER NOT NULL DEFAULT 1,
			created_by TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		);
		CREATE TABLE website_domains (
			website_id TEXT NOT NULL,
			domain TEXT NOT NULL UNIQUE,
			primary_domain INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY(website_id,domain),
			FOREIGN KEY(website_id) REFERENCES websites(id) ON DELETE CASCADE
		);
		CREATE TABLE website_revisions (
			id TEXT PRIMARY KEY,
			website_id TEXT NOT NULL,
			sequence INTEGER NOT NULL,
			configuration_json TEXT NOT NULL,
			created_by TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			UNIQUE(website_id,sequence),
			FOREIGN KEY(website_id) REFERENCES websites(id) ON DELETE CASCADE
		);
		CREATE TABLE operation_jobs (
			id TEXT PRIMARY KEY,
			kind TEXT NOT NULL,
			target_type TEXT NOT NULL,
			target_id TEXT NOT NULL,
			state TEXT NOT NULL,
			requested_by TEXT NOT NULL,
			request_json TEXT NOT NULL DEFAULT '{}',
			result TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			started_at INTEGER,
			finished_at INTEGER
		);
		CREATE INDEX operation_jobs_state_created_idx ON operation_jobs(state,created_at);`,
	},
	{
		version: 6,
		name:    "legacy state migration",
		sql: `CREATE TABLE accounts (
			id TEXT PRIMARY KEY,
			display_name TEXT NOT NULL,
			enabled INTEGER NOT NULL,
			created_at INTEGER NOT NULL
		);
		CREATE TABLE login_identities (
			id TEXT PRIMARY KEY,
			account_id TEXT NOT NULL,
			type TEXT NOT NULL,
			username TEXT NOT NULL DEFAULT '',
			email TEXT NOT NULL DEFAULT '',
			provider_subject TEXT NOT NULL DEFAULT '',
			password_hash TEXT NOT NULL DEFAULT '',
			totp_enabled INTEGER NOT NULL DEFAULT 0,
			recovery_code_hashes_json TEXT NOT NULL DEFAULT '[]',
			enabled INTEGER NOT NULL,
			FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE
		);
		CREATE UNIQUE INDEX login_identity_username_idx ON login_identities(username) WHERE username<>'';
		CREATE UNIQUE INDEX login_identity_provider_idx ON login_identities(type,provider_subject) WHERE provider_subject<>'';
		CREATE TABLE roles (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			built_in INTEGER NOT NULL DEFAULT 0
		);
		CREATE TABLE role_capabilities (
			role_id TEXT NOT NULL,
			capability TEXT NOT NULL,
			PRIMARY KEY(role_id,capability),
			FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE
		);
		CREATE TABLE account_roles (
			account_id TEXT NOT NULL,
			role_id TEXT NOT NULL,
			PRIMARY KEY(account_id,role_id),
			FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE,
			FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE
		);
		CREATE TABLE browser_sessions (
			id TEXT PRIMARY KEY,
			account_id TEXT NOT NULL,
			identity_id TEXT NOT NULL,
			csrf TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			remote_ip TEXT NOT NULL DEFAULT '',
			user_agent TEXT NOT NULL DEFAULT '',
			FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE
		);
		CREATE TABLE ai_usage_totals (
			account_id TEXT NOT NULL,
			provider TEXT NOT NULL,
			requests INTEGER NOT NULL,
			input_tokens INTEGER NOT NULL,
			output_tokens INTEGER NOT NULL,
			estimated_cost_usd REAL NOT NULL,
			updated_at INTEGER NOT NULL,
			PRIMARY KEY(account_id,provider)
		);
		CREATE TABLE audit_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			source_key TEXT UNIQUE,
			event TEXT NOT NULL,
			account_id TEXT NOT NULL DEFAULT '',
			identity_id TEXT NOT NULL DEFAULT '',
			remote_ip TEXT NOT NULL DEFAULT '',
			detail TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL
		);
		CREATE INDEX audit_events_created_idx ON audit_events(created_at DESC);
		CREATE TABLE legacy_imports (
			name TEXT PRIMARY KEY,
			imported_at INTEGER NOT NULL,
			detail TEXT NOT NULL DEFAULT ''
		);`,
	},
	{
		version: 7,
		name:    "structured audit evidence",
		sql: `ALTER TABLE audit_events ADD COLUMN schema_version INTEGER NOT NULL DEFAULT 1;
		ALTER TABLE audit_events ADD COLUMN request_id TEXT NOT NULL DEFAULT '';
		ALTER TABLE audit_events ADD COLUMN action TEXT NOT NULL DEFAULT '';
		ALTER TABLE audit_events ADD COLUMN target TEXT NOT NULL DEFAULT '';
		ALTER TABLE audit_events ADD COLUMN outcome TEXT NOT NULL DEFAULT 'success';
		CREATE INDEX audit_events_request_idx ON audit_events(request_id);`,
	},
	{
		version: 8,
		name:    "image attachment names",
		sql:     `ALTER TABLE conversation_events ADD COLUMN name TEXT NOT NULL DEFAULT '';`,
	},
}

func openDatabase(configDir string) (*sql.DB, error) {
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(configDir, "warden.db")
	u := &url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	q := u.Query()
	q.Set("mode", "rwc")
	q.Set("_busy_timeout", "5000")
	q.Set("_foreign_keys", "on")
	q.Set("_journal_mode", "WAL")
	q.Set("_synchronous", "FULL")
	q.Set("_defensive", "true")
	q.Set("_dqs", "false")
	u.RawQuery = q.Encode()

	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetConnMaxLifetime(0)
	db.SetMaxIdleConns(4)
	db.SetMaxOpenConns(8)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("open Warden database: %w", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		db.Close()
		return nil, fmt.Errorf("protect Warden database: %w", err)
	}
	if err := migrateDatabase(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	var integrity string
	if err := db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&integrity); err != nil || integrity != "ok" {
		db.Close()
		if err != nil {
			return nil, fmt.Errorf("check Warden database integrity: %w", err)
		}
		return nil, fmt.Errorf("check Warden database integrity: %s", integrity)
	}
	return db, nil
}

func migrateDatabase(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		name TEXT NOT NULL,
		applied_at INTEGER NOT NULL
	)`); err != nil {
		return fmt.Errorf("create migration table: %w", err)
	}
	var current int
	if err := db.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&current); err != nil {
		return fmt.Errorf("read database schema: %w", err)
	}
	if current > len(databaseMigrations) {
		return fmt.Errorf("Warden database schema %d is newer than supported schema %d", current, len(databaseMigrations))
	}
	for _, migration := range databaseMigrations {
		if migration.version <= current {
			continue
		}
		conn, err := db.Conn(ctx)
		if err != nil {
			return fmt.Errorf("reserve migration connection %d: %w", migration.version, err)
		}
		if _, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
			conn.Close()
			return fmt.Errorf("begin migration %d: %w", migration.version, err)
		}
		var lockedCurrent int
		err = conn.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&lockedCurrent)
		if err == nil && lockedCurrent < migration.version {
			_, err = conn.ExecContext(ctx, migration.sql)
		}
		if err == nil && lockedCurrent < migration.version {
			_, err = conn.ExecContext(ctx, "INSERT INTO schema_migrations(version,name,applied_at) VALUES(?,?,?)", migration.version, migration.name, time.Now().UnixMilli())
		}
		if err != nil {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
			conn.Close()
			return fmt.Errorf("apply migration %d (%s): %w", migration.version, migration.name, err)
		}
		if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
			conn.Close()
			return fmt.Errorf("commit migration %d: %w", migration.version, err)
		}
		conn.Close()
		current = migration.version
	}
	return nil
}
