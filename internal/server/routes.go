package server

import "net/http"

type routePolicy struct {
	Path       string
	Boundary   string
	Capability string
}

type registeredRoute struct {
	Policy  routePolicy
	Handler http.HandlerFunc
}

func (a *app) apiRoutes() []registeredRoute {
	public := func(path string, handler http.HandlerFunc) registeredRoute {
		return registeredRoute{routePolicy{Path: path, Boundary: "public"}, handler}
	}
	session := func(path string, handler http.HandlerFunc) registeredRoute {
		return registeredRoute{routePolicy{Path: path, Boundary: "session"}, a.protect(handler)}
	}
	capability := func(path, cap string, handler http.HandlerFunc) registeredRoute {
		return registeredRoute{routePolicy{Path: path, Boundary: "capability", Capability: cap}, a.require(cap, handler)}
	}
	return []registeredRoute{
		public("/api/setup/status", a.setupStatus), public("/api/setup", a.setup),
		public("/api/login", a.login), public("/api/login/totp", a.loginTOTP),
		public("/api/oauth/google/start", a.googleStart), public("/api/oauth/google/callback", a.googleCallback),
		public("/api/launcher/instances", a.launcherInstances), capability("/api/launcher/config", "launcher.configure.all", a.launcherConfig),
		capability("/api/manage/users", "accounts.manage", a.manageUsers), capability("/api/manage/users/action", "accounts.manage", userManagementActions(a.accessAction)),
		capability("/api/manage/roles", "roles.manage", a.manageRoles), capability("/api/manage/roles/action", "roles.manage", roleManagementActions(a.accessAction)),
		session("/api/security", a.security), session("/api/ai", a.aiSettings),
		capability("/api/agent/status", "agent.run", a.agentStatus), capability("/api/agent/run", "agent.run", a.agentRun),
		capability("/api/agent/cancel", "agent.run", a.agentCancel), capability("/api/agent/run-diagnostics", "agent.run", a.agentRunDiagnostics),
		capability("/api/agent/image", "agent.run", a.agentImage), capability("/api/agent/models", "ai.use", a.agentModels),
		capability("/api/agent/conversations", "agent.run", a.conversationsAPI), capability("/api/agent/conversation", "agent.run", a.conversationAPI),
		session("/api/logout", a.logout), public("/api/session", a.session),
		capability("/api/monitor", "monitor.read", a.monitor), capability("/api/alerts", "monitor.read", a.alertsAPI),
		capability("/api/websites", "system.read", a.websitesAPI), capability("/api/files", "files.read", a.listFiles),
		session("/api/file", a.file), capability("/api/files/mutate", "files.manage", a.mutate),
		capability("/api/files/archive", "files.read", a.archiveDownload), capability("/api/files/compress", "files.manage", a.compress),
		capability("/api/files/extract", "files.manage", a.extract), capability("/api/workspace/search", "workspace.search", a.workspaceSearch),
		capability("/api/workspace/replace", "workspace.replace", a.workspaceReplace), capability("/api/workspace/replace/undo", "workspace.replace", a.workspaceUndoReplace),
		capability("/api/source-control/status", "source.read", a.sourceControlStatus), capability("/api/source-control/mutate", "source.write", a.sourceControlMutate),
		session("/api/admin/", a.admin), capability("/api/warden/export", "settings.manage", a.exportConfiguration),
		capability("/api/warden/import", "settings.manage", a.importConfiguration), capability("/api/warden/export-secure", "settings.manage", a.exportSecureConfiguration),
		capability("/api/warden/import-secure", "settings.manage", a.importSecureConfiguration),
		{routePolicy{Path: "/api/terminal", Boundary: "websocket", Capability: "terminal.open"}, a.terminal},
		capability("/api/terminal/sessions", "terminal.open", a.terminalSessionsAPI),
	}
}

// OperationRoute is the runtime API evidence used by the Phase-5 operation
// coverage manifest. Methods reflect the handlers actually exposed on each
// registered route; the /api/admin/ prefix is expanded into its supported
// resource/action paths so coverage is expressed at callable-operation level.
type OperationRoute struct {
	Method     string
	Path       string
	Boundary   string
	Capability string
}

func (a *app) OperationRouteInventory() []OperationRoute {
	methods := map[string][]string{
		"/api/setup/status": {http.MethodGet}, "/api/setup": {http.MethodPost}, "/api/login": {http.MethodPost}, "/api/login/totp": {http.MethodPost},
		"/api/oauth/google/start": {http.MethodGet}, "/api/oauth/google/callback": {http.MethodGet}, "/api/launcher/instances": {http.MethodGet}, "/api/launcher/config": {http.MethodPut},
		"/api/manage/users": {http.MethodGet}, "/api/manage/users/action": {http.MethodPost}, "/api/manage/roles": {http.MethodGet}, "/api/manage/roles/action": {http.MethodPost},
		"/api/security": {http.MethodGet, http.MethodPost}, "/api/ai": {http.MethodGet, http.MethodPost},
		"/api/agent/status": {http.MethodGet}, "/api/agent/run": {http.MethodPost}, "/api/agent/cancel": {http.MethodPost}, "/api/agent/run-diagnostics": {http.MethodGet}, "/api/agent/image": {http.MethodGet}, "/api/agent/models": {http.MethodGet},
		"/api/agent/conversations": {http.MethodGet}, "/api/agent/conversation": {http.MethodPut, http.MethodDelete},
		"/api/logout": {http.MethodPost}, "/api/session": {http.MethodGet}, "/api/monitor": {http.MethodGet}, "/api/alerts": {http.MethodGet, http.MethodPost}, "/api/websites": {http.MethodGet, http.MethodPost},
		"/api/files": {http.MethodGet}, "/api/file": {http.MethodGet, http.MethodPut}, "/api/files/mutate": {http.MethodPost}, "/api/files/archive": {http.MethodGet}, "/api/files/compress": {http.MethodPost}, "/api/files/extract": {http.MethodPost},
		"/api/workspace/search": {http.MethodGet}, "/api/workspace/replace": {http.MethodPost}, "/api/workspace/replace/undo": {http.MethodPost}, "/api/source-control/status": {http.MethodGet}, "/api/source-control/mutate": {http.MethodPost},
		"/api/warden/export": {http.MethodGet}, "/api/warden/import": {http.MethodPost}, "/api/warden/export-secure": {http.MethodPost}, "/api/warden/import-secure": {http.MethodPost},
		"/api/terminal": {http.MethodGet}, "/api/terminal/sessions": {http.MethodGet, http.MethodPut, http.MethodDelete},
	}
	out := make([]OperationRoute, 0, 80)
	for _, r := range a.apiRoutes() {
		if r.Policy.Path == "/api/admin/" {
			continue
		}
		for _, method := range methods[r.Policy.Path] {
			out = append(out, OperationRoute{Method: method, Path: r.Policy.Path, Boundary: r.Policy.Boundary, Capability: r.Policy.Capability})
		}
	}
	for _, kind := range []string{"certs", "cron", "docker", "fail2ban", "firewall", "services", "ssh", "users", "warden", "access", "audit"} {
		capability := requiredAdminCapability(kind, http.MethodGet)
		out = append(out, OperationRoute{Method: http.MethodGet, Path: "/api/admin/" + kind, Boundary: "capability", Capability: capability})
		if kind != "audit" {
			out = append(out, OperationRoute{Method: http.MethodPost, Path: "/api/admin/" + kind + "/action", Boundary: "capability", Capability: requiredAdminCapability(kind, http.MethodPost)})
		}
	}
	return out
}

func OperationRouteInventory() []OperationRoute { return (&app{}).OperationRouteInventory() }
