// Package operations declares Warden's canonical functional operation surface.
package operations

import (
	"github.com/gantry-tools/gantry-core/contracttest"
	"github.com/gantry-tools/gantry-core/operation"
	"github.com/warden-cv/warden/internal/server"
)

type spec struct {
	id, method, path, resource, verb string
	kind                             operation.Kind
	automation                       operation.Automation
	website                          bool
	test                             string
	capability                       string
	secrets                          []string
}

func s(id, method, path, resource, verb string, kind operation.Kind, test string) spec {
	return spec{id: id, method: method, path: path, resource: resource, verb: verb, kind: kind, automation: operation.Automatable, website: true, test: test}
}

var specs = []spec{
	s("warden.setup.status", "GET", "/api/setup/status", "setup", "status", operation.Read, "internal/server/server_test.go"),
	s("warden.setup.apply", "POST", "/api/setup", "setup", "apply", operation.Mutation, "internal/server/server_test.go"),
	s("warden.auth.login", "POST", "/api/login", "auth", "login", operation.Mutation, "internal/server/security_test.go"),
	s("warden.auth.totp.login", "POST", "/api/login/totp", "auth", "totp-login", operation.Mutation, "internal/server/security_test.go"),
	{id: "warden.oauth.google.start", method: "GET", path: "/api/oauth/google/start", kind: operation.Read, automation: operation.BrowserProtocol, website: true, test: "internal/server/google_test.go"},
	{id: "warden.oauth.google.callback", method: "GET", path: "/api/oauth/google/callback", kind: operation.Read, automation: operation.BrowserProtocol, website: false, test: "internal/server/google_test.go"},
	s("warden.launcher.instances.list", "GET", "/api/launcher/instances", "launcher-instances", "list", operation.Read, "internal/server/launcher_test.go"),
	s("warden.launcher.config.update", "PUT", "/api/launcher/config", "launcher-config", "update", operation.Mutation, "internal/server/launcher_test.go"),
	s("warden.users.list", "GET", "/api/manage/users", "users", "list", operation.Read, "internal/server/manage_test.go"),
	s("warden.users.action", "POST", "/api/manage/users/action", "users", "action", operation.Destructive, "internal/server/manage_test.go"),
	s("warden.roles.list", "GET", "/api/manage/roles", "roles", "list", operation.Read, "internal/server/manage_test.go"),
	s("warden.roles.action", "POST", "/api/manage/roles/action", "roles", "action", operation.Destructive, "internal/server/manage_test.go"),
	s("warden.security.read", "GET", "/api/security", "security", "get", operation.Read, "internal/server/security_test.go"),
	s("warden.security.update", "POST", "/api/security", "security", "update", operation.Mutation, "internal/server/security_test.go"),
	s("warden.ai.read", "GET", "/api/ai", "ai", "get", operation.Read, "internal/server/ai_test.go"),
	s("warden.ai.update", "POST", "/api/ai", "ai", "update", operation.Mutation, "internal/server/ai_test.go"),
	s("warden.agent.status", "GET", "/api/agent/status", "agent", "status", operation.Read, "internal/server/agent_test.go"),
	{id: "warden.agent.run", method: "POST", path: "/api/agent/run", resource: "agent", verb: "run", kind: operation.Mutation, automation: operation.StreamingProtocol, website: true, test: "internal/server/agent_test.go"},
	s("warden.agent.cancel", "POST", "/api/agent/cancel", "agent", "cancel", operation.Mutation, "internal/server/agent_test.go"),
	s("warden.agent.diagnostics", "GET", "/api/agent/run-diagnostics", "agent", "diagnostics", operation.Read, "internal/server/agent_test.go"),
	s("warden.agent.image", "GET", "/api/agent/image", "agent", "image", operation.Read, "internal/server/agent_test.go"),
	s("warden.agent.models", "GET", "/api/agent/models", "agent", "models", operation.Read, "internal/server/agent_test.go"),
	s("warden.conversations.list", "GET", "/api/agent/conversations", "conversations", "list", operation.Read, "internal/server/conversations_test.go"),
	s("warden.conversation.update", "PUT", "/api/agent/conversation", "conversation", "update", operation.Mutation, "internal/server/conversations_test.go"),
	s("warden.conversation.delete", "DELETE", "/api/agent/conversation", "conversation", "delete", operation.Destructive, "internal/server/conversations_test.go"),
	s("warden.auth.logout", "POST", "/api/logout", "auth", "logout", operation.Destructive, "internal/server/server_test.go"),
	s("warden.auth.session", "GET", "/api/session", "auth", "session", operation.Read, "internal/server/server_test.go"),
	s("warden.monitor.read", "GET", "/api/monitor", "monitor", "get", operation.Read, "internal/server/monitor_test.go"),
	s("warden.alerts.list", "GET", "/api/alerts", "alerts", "list", operation.Read, "internal/server/alerts_test.go"),
	s("warden.alerts.update", "POST", "/api/alerts", "alerts", "update", operation.Mutation, "internal/server/alerts_test.go"),
	s("warden.websites.list", "GET", "/api/websites", "websites", "list", operation.Read, "internal/server/websites_test.go"),
	s("warden.websites.update", "POST", "/api/websites", "websites", "update", operation.Mutation, "internal/server/websites_test.go"),
	s("warden.files.list", "GET", "/api/files", "files", "list", operation.Read, "internal/server/files_test.go"),
	func() spec {
		x := s("warden.file.read", "GET", "/api/file", "file", "get", operation.Read, "internal/server/files_test.go")
		x.capability = "files.read"
		return x
	}(),
	func() spec {
		x := s("warden.file.write", "PUT", "/api/file", "file", "write", operation.Mutation, "internal/server/files_test.go")
		x.capability = "files.write"
		return x
	}(),
	s("warden.files.mutate", "POST", "/api/files/mutate", "files", "mutate", operation.Destructive, "internal/server/files_test.go"),
	s("warden.files.archive", "GET", "/api/files/archive", "files", "archive", operation.Read, "internal/server/archives_test.go"),
	s("warden.files.compress", "POST", "/api/files/compress", "files", "compress", operation.Mutation, "internal/server/archives_test.go"),
	s("warden.files.extract", "POST", "/api/files/extract", "files", "extract", operation.Mutation, "internal/server/archives_test.go"),
	s("warden.workspace.search", "GET", "/api/workspace/search", "workspace", "search", operation.Read, "internal/server/workspace_test.go"),
	s("warden.workspace.replace", "POST", "/api/workspace/replace", "workspace", "replace", operation.Mutation, "internal/server/workspace_test.go"),
	s("warden.workspace.undo", "POST", "/api/workspace/replace/undo", "workspace", "undo", operation.Mutation, "internal/server/workspace_test.go"),
	s("warden.source.status", "GET", "/api/source-control/status", "source-control", "status", operation.Read, "internal/server/sourcecontrol_test.go"),
	s("warden.source.mutate", "POST", "/api/source-control/mutate", "source-control", "mutate", operation.Mutation, "internal/server/sourcecontrol_test.go"),
	s("warden.config.export", "GET", "/api/warden/export", "config", "export", operation.Read, "internal/server/lifecycle_test.go"),
	s("warden.config.import", "POST", "/api/warden/import", "config", "import", operation.Destructive, "internal/server/lifecycle_test.go"),
	s("warden.config.secure-export", "POST", "/api/warden/export-secure", "config", "secure-export", operation.Mutation, "internal/server/backup_test.go"),
	s("warden.config.secure-import", "POST", "/api/warden/import-secure", "config", "secure-import", operation.Destructive, "internal/server/backup_test.go"),
	{id: "warden.terminal.open", method: "GET", path: "/api/terminal", kind: operation.Read, automation: operation.StreamingProtocol, website: true, test: "internal/server/terminal_test.go", capability: "terminal.open"},
	s("warden.terminal-sessions.list", "GET", "/api/terminal/sessions", "terminal-sessions", "list", operation.Read, "internal/server/terminal_sessions_test.go"),
	s("warden.terminal-sessions.update", "PUT", "/api/terminal/sessions", "terminal-sessions", "update", operation.Mutation, "internal/server/terminal_sessions_test.go"),
	s("warden.terminal-sessions.delete", "DELETE", "/api/terminal/sessions", "terminal-sessions", "delete", operation.Destructive, "internal/server/terminal_sessions_test.go"),
}

func init() {
	for _, kind := range []string{"certs", "cron", "docker", "fail2ban", "firewall", "services", "ssh", "users", "warden", "access", "audit"} {
		cap := "system.read"
		if kind == "warden" {
			cap = "settings.manage"
		} else if kind == "access" {
			cap = "accounts.manage"
		} else if kind == "audit" {
			cap = "audit.read"
		}
		specs = append(specs, spec{id: "warden.admin." + kind + ".read", method: "GET", path: "/api/admin/" + kind, resource: "admin-" + kind, verb: "get", kind: operation.Read, automation: operation.Automatable, website: true, test: "internal/server/admin_test.go", capability: cap})
		if kind != "audit" {
			writeCap := "system.manage"
			if kind == "warden" {
				writeCap = "settings.manage"
			} else if kind == "access" {
				writeCap = "accounts.manage"
			}
			specs = append(specs, spec{id: "warden.admin." + kind + ".action", method: "POST", path: "/api/admin/" + kind + "/action", resource: "admin-" + kind, verb: "action", kind: operation.Mutation, automation: operation.Automatable, website: true, test: "internal/server/admin_test.go", capability: writeCap})
		}
	}
	for i := range specs {
		switch specs[i].id {
		case "warden.auth.login", "warden.auth.totp.login":
			specs[i].secrets = []string{"/password", "/code"}
		case "warden.setup.apply":
			specs[i].secrets = []string{"/password"}
		case "warden.security.update", "warden.ai.update", "warden.config.secure-import", "warden.config.secure-export":
			specs[i].secrets = []string{"/password"}
		}
	}
}

var Contracts = buildContracts()

func buildContracts() []operation.Contract {
	inventory := map[string]server.OperationRoute{}
	for _, r := range server.OperationRouteInventory() {
		inventory[r.Method+" "+r.Path] = r
	}
	out := make([]operation.Contract, 0, len(specs))
	for _, sp := range specs {
		r := inventory[sp.method+" "+sp.path]
		boundary := operation.Session
		switch r.Boundary {
		case "public":
			boundary = operation.Public
		case "capability":
			boundary = operation.Capability
		case "websocket":
			boundary = operation.Capability
		}
		capability := r.Capability
		if sp.capability != "" {
			boundary, capability = operation.Capability, sp.capability
		}
		auth := operation.Authorization{Boundary: boundary}
		if boundary == operation.Capability {
			auth.Capability = capability
		}
		var cli *operation.CLI
		if sp.resource != "" {
			cli = &operation.CLI{Resource: sp.resource, Verb: sp.verb, Implemented: true}
		}
		audit := operation.Audit{}
		if sp.kind != operation.Read {
			audit = operation.Audit{Required: true, Event: sp.id + ".performed"}
		}
		schemas := operation.Schemas{Output: sp.id + ".response.v1"}
		if sp.kind != operation.Read {
			schemas.Input = sp.id + ".request.v1"
		}
		out = append(out, operation.Contract{SchemaVersion: operation.SchemaVersion, ID: sp.id, Kind: sp.kind, Route: operation.Route{Method: sp.method, Path: sp.path}, CLI: cli, Authorization: auth, Schemas: schemas, Audit: audit, Idempotency: operation.Idempotency{RetrySafe: sp.kind == operation.Read}, Automation: sp.automation, SecretInputs: append([]string(nil), sp.secrets...)})
	}
	return out
}

func Manifest() contracttest.Manifest {
	routes := make([]operation.Route, 0)
	for _, r := range server.OperationRouteInventory() {
		routes = append(routes, operation.Route{Method: r.Method, Path: r.Path})
	}
	commands := make([]operation.CLI, 0)
	website := make([]string, 0)
	evidence := map[string]contracttest.Evidence{}
	for i, c := range Contracts {
		if c.CLI != nil && c.CLI.Implemented {
			commands = append(commands, *c.CLI)
		}
		if specs[i].website {
			website = append(website, c.ID)
		}
		evidence[c.ID] = contracttest.Evidence{Website: specs[i].website, Tests: []string{specs[i].test}}
	}
	return contracttest.Manifest{SchemaVersion: 1, Project: "warden", Operations: Contracts, ObservedRoutes: routes, ObservedCommands: commands, WebsiteOperations: website, Evidence: evidence}
}

func AdoptionManifest() contracttest.Manifest { return Manifest() }
