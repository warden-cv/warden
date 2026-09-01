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
