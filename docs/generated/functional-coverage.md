# warden functional coverage

Generated from the tested operation manifest. Do not edit by hand.

| Operation | Website | API | CLI | Permission | Schemas | Tests |
| --- | :---: | --- | --- | --- | --- | --- |
| `warden.admin.access.action` | yes | `POST /api/admin/access/action` | `admin-access action` | `capability:accounts.manage` | `warden.admin.access.action.request.v1 → warden.admin.access.action.response.v1` | internal/server/admin_test.go |
| `warden.admin.access.read` | yes | `GET /api/admin/access` | `admin-access get` | `capability:accounts.manage` | `— → warden.admin.access.read.response.v1` | internal/server/admin_test.go |
| `warden.admin.audit.read` | yes | `GET /api/admin/audit` | `admin-audit get` | `capability:audit.read` | `— → warden.admin.audit.read.response.v1` | internal/server/admin_test.go |
| `warden.admin.certs.action` | yes | `POST /api/admin/certs/action` | `admin-certs action` | `capability:system.manage` | `warden.admin.certs.action.request.v1 → warden.admin.certs.action.response.v1` | internal/server/admin_test.go |
| `warden.admin.certs.read` | yes | `GET /api/admin/certs` | `admin-certs get` | `capability:system.read` | `— → warden.admin.certs.read.response.v1` | internal/server/admin_test.go |
| `warden.admin.cron.action` | yes | `POST /api/admin/cron/action` | `admin-cron action` | `capability:system.manage` | `warden.admin.cron.action.request.v1 → warden.admin.cron.action.response.v1` | internal/server/admin_test.go |
| `warden.admin.cron.read` | yes | `GET /api/admin/cron` | `admin-cron get` | `capability:system.read` | `— → warden.admin.cron.read.response.v1` | internal/server/admin_test.go |
| `warden.admin.docker.action` | yes | `POST /api/admin/docker/action` | `admin-docker action` | `capability:system.manage` | `warden.admin.docker.action.request.v1 → warden.admin.docker.action.response.v1` | internal/server/admin_test.go |
| `warden.admin.docker.read` | yes | `GET /api/admin/docker` | `admin-docker get` | `capability:system.read` | `— → warden.admin.docker.read.response.v1` | internal/server/admin_test.go |
| `warden.admin.fail2ban.action` | yes | `POST /api/admin/fail2ban/action` | `admin-fail2ban action` | `capability:system.manage` | `warden.admin.fail2ban.action.request.v1 → warden.admin.fail2ban.action.response.v1` | internal/server/admin_test.go |
| `warden.admin.fail2ban.read` | yes | `GET /api/admin/fail2ban` | `admin-fail2ban get` | `capability:system.read` | `— → warden.admin.fail2ban.read.response.v1` | internal/server/admin_test.go |
| `warden.admin.firewall.action` | yes | `POST /api/admin/firewall/action` | `admin-firewall action` | `capability:system.manage` | `warden.admin.firewall.action.request.v1 → warden.admin.firewall.action.response.v1` | internal/server/admin_test.go |
| `warden.admin.firewall.read` | yes | `GET /api/admin/firewall` | `admin-firewall get` | `capability:system.read` | `— → warden.admin.firewall.read.response.v1` | internal/server/admin_test.go |
| `warden.admin.services.action` | yes | `POST /api/admin/services/action` | `admin-services action` | `capability:system.manage` | `warden.admin.services.action.request.v1 → warden.admin.services.action.response.v1` | internal/server/admin_test.go |
| `warden.admin.services.read` | yes | `GET /api/admin/services` | `admin-services get` | `capability:system.read` | `— → warden.admin.services.read.response.v1` | internal/server/admin_test.go |
| `warden.admin.ssh.action` | yes | `POST /api/admin/ssh/action` | `admin-ssh action` | `capability:system.manage` | `warden.admin.ssh.action.request.v1 → warden.admin.ssh.action.response.v1` | internal/server/admin_test.go |
| `warden.admin.ssh.read` | yes | `GET /api/admin/ssh` | `admin-ssh get` | `capability:system.read` | `— → warden.admin.ssh.read.response.v1` | internal/server/admin_test.go |
| `warden.admin.users.action` | yes | `POST /api/admin/users/action` | `admin-users action` | `capability:system.manage` | `warden.admin.users.action.request.v1 → warden.admin.users.action.response.v1` | internal/server/admin_test.go |
| `warden.admin.users.read` | yes | `GET /api/admin/users` | `admin-users get` | `capability:system.read` | `— → warden.admin.users.read.response.v1` | internal/server/admin_test.go |
| `warden.admin.warden.action` | yes | `POST /api/admin/warden/action` | `admin-warden action` | `capability:settings.manage` | `warden.admin.warden.action.request.v1 → warden.admin.warden.action.response.v1` | internal/server/admin_test.go |
| `warden.admin.warden.read` | yes | `GET /api/admin/warden` | `admin-warden get` | `capability:settings.manage` | `— → warden.admin.warden.read.response.v1` | internal/server/admin_test.go |
| `warden.agent.cancel` | yes | `POST /api/agent/cancel` | `agent cancel` | `capability:agent.run` | `warden.agent.cancel.request.v1 → warden.agent.cancel.response.v1` | internal/server/agent_test.go |
| `warden.agent.diagnostics` | yes | `GET /api/agent/run-diagnostics` | `agent diagnostics` | `capability:agent.run` | `— → warden.agent.diagnostics.response.v1` | internal/server/agent_test.go |
| `warden.agent.image` | yes | `GET /api/agent/image` | `agent image` | `capability:agent.run` | `— → warden.agent.image.response.v1` | internal/server/agent_test.go |
| `warden.agent.models` | yes | `GET /api/agent/models` | `agent models` | `capability:ai.use` | `— → warden.agent.models.response.v1` | internal/server/agent_test.go |
| `warden.agent.run` | yes | `POST /api/agent/run` | `agent run` | `capability:agent.run` | `warden.agent.run.request.v1 → warden.agent.run.response.v1` | internal/server/agent_test.go |
| `warden.agent.status` | yes | `GET /api/agent/status` | `agent status` | `capability:agent.run` | `— → warden.agent.status.response.v1` | internal/server/agent_test.go |
| `warden.ai.read` | yes | `GET /api/ai` | `ai get` | `session` | `— → warden.ai.read.response.v1` | internal/server/ai_test.go |
| `warden.ai.update` | yes | `POST /api/ai` | `ai update` | `session` | `warden.ai.update.request.v1 → warden.ai.update.response.v1` | internal/server/ai_test.go |
| `warden.alerts.list` | yes | `GET /api/alerts` | `alerts list` | `capability:monitor.read` | `— → warden.alerts.list.response.v1` | internal/server/alerts_test.go |
| `warden.alerts.update` | yes | `POST /api/alerts` | `alerts update` | `capability:monitor.read` | `warden.alerts.update.request.v1 → warden.alerts.update.response.v1` | internal/server/alerts_test.go |
| `warden.auth.login` | yes | `POST /api/login` | `auth login` | `public` | `warden.auth.login.request.v1 → warden.auth.login.response.v1` | internal/server/security_test.go |
| `warden.auth.logout` | yes | `POST /api/logout` | `auth logout` | `session` | `warden.auth.logout.request.v1 → warden.auth.logout.response.v1` | internal/server/server_test.go |
| `warden.auth.session` | yes | `GET /api/session` | `auth session` | `public` | `— → warden.auth.session.response.v1` | internal/server/server_test.go |
| `warden.auth.totp.login` | yes | `POST /api/login/totp` | `auth totp-login` | `public` | `warden.auth.totp.login.request.v1 → warden.auth.totp.login.response.v1` | internal/server/security_test.go |
| `warden.config.export` | yes | `GET /api/warden/export` | `config export` | `capability:settings.manage` | `— → warden.config.export.response.v1` | internal/server/lifecycle_test.go |
| `warden.config.import` | yes | `POST /api/warden/import` | `config import` | `capability:settings.manage` | `warden.config.import.request.v1 → warden.config.import.response.v1` | internal/server/lifecycle_test.go |
| `warden.config.secure-export` | yes | `POST /api/warden/export-secure` | `config secure-export` | `capability:settings.manage` | `warden.config.secure-export.request.v1 → warden.config.secure-export.response.v1` | internal/server/backup_test.go |
| `warden.config.secure-import` | yes | `POST /api/warden/import-secure` | `config secure-import` | `capability:settings.manage` | `warden.config.secure-import.request.v1 → warden.config.secure-import.response.v1` | internal/server/backup_test.go |
| `warden.conversation.delete` | yes | `DELETE /api/agent/conversation` | `conversation delete` | `capability:agent.run` | `warden.conversation.delete.request.v1 → warden.conversation.delete.response.v1` | internal/server/conversations_test.go |
| `warden.conversation.update` | yes | `PUT /api/agent/conversation` | `conversation update` | `capability:agent.run` | `warden.conversation.update.request.v1 → warden.conversation.update.response.v1` | internal/server/conversations_test.go |
| `warden.conversations.list` | yes | `GET /api/agent/conversations` | `conversations list` | `capability:agent.run` | `— → warden.conversations.list.response.v1` | internal/server/conversations_test.go |
| `warden.file.read` | yes | `GET /api/file` | `file get` | `capability:files.read` | `— → warden.file.read.response.v1` | internal/server/files_test.go |
| `warden.file.write` | yes | `PUT /api/file` | `file write` | `capability:files.write` | `warden.file.write.request.v1 → warden.file.write.response.v1` | internal/server/files_test.go |
| `warden.files.archive` | yes | `GET /api/files/archive` | `files archive` | `capability:files.read` | `— → warden.files.archive.response.v1` | internal/server/archives_test.go |
| `warden.files.compress` | yes | `POST /api/files/compress` | `files compress` | `capability:files.manage` | `warden.files.compress.request.v1 → warden.files.compress.response.v1` | internal/server/archives_test.go |
| `warden.files.extract` | yes | `POST /api/files/extract` | `files extract` | `capability:files.manage` | `warden.files.extract.request.v1 → warden.files.extract.response.v1` | internal/server/archives_test.go |
| `warden.files.list` | yes | `GET /api/files` | `files list` | `capability:files.read` | `— → warden.files.list.response.v1` | internal/server/files_test.go |
| `warden.files.mutate` | yes | `POST /api/files/mutate` | `files mutate` | `capability:files.manage` | `warden.files.mutate.request.v1 → warden.files.mutate.response.v1` | internal/server/files_test.go |
| `warden.launcher.config.update` | yes | `PUT /api/launcher/config` | `launcher-config update` | `capability:launcher.configure.all` | `warden.launcher.config.update.request.v1 → warden.launcher.config.update.response.v1` | internal/server/launcher_test.go |
| `warden.launcher.instances.list` | yes | `GET /api/launcher/instances` | `launcher-instances list` | `public` | `— → warden.launcher.instances.list.response.v1` | internal/server/launcher_test.go |
| `warden.monitor.read` | yes | `GET /api/monitor` | `monitor get` | `capability:monitor.read` | `— → warden.monitor.read.response.v1` | internal/server/monitor_test.go |
| `warden.oauth.google.callback` | no | `GET /api/oauth/google/callback` | `—` | `public` | `— → warden.oauth.google.callback.response.v1` | internal/server/google_test.go |
| `warden.oauth.google.start` | yes | `GET /api/oauth/google/start` | `—` | `public` | `— → warden.oauth.google.start.response.v1` | internal/server/google_test.go |
| `warden.roles.action` | yes | `POST /api/manage/roles/action` | `roles action` | `capability:roles.manage` | `warden.roles.action.request.v1 → warden.roles.action.response.v1` | internal/server/manage_test.go |
| `warden.roles.list` | yes | `GET /api/manage/roles` | `roles list` | `capability:roles.manage` | `— → warden.roles.list.response.v1` | internal/server/manage_test.go |
| `warden.security.read` | yes | `GET /api/security` | `security get` | `session` | `— → warden.security.read.response.v1` | internal/server/security_test.go |
| `warden.security.update` | yes | `POST /api/security` | `security update` | `session` | `warden.security.update.request.v1 → warden.security.update.response.v1` | internal/server/security_test.go |
| `warden.setup.apply` | yes | `POST /api/setup` | `setup apply` | `public` | `warden.setup.apply.request.v1 → warden.setup.apply.response.v1` | internal/server/server_test.go |
| `warden.setup.status` | yes | `GET /api/setup/status` | `setup status` | `public` | `— → warden.setup.status.response.v1` | internal/server/server_test.go |
| `warden.source.mutate` | yes | `POST /api/source-control/mutate` | `source-control mutate` | `capability:source.write` | `warden.source.mutate.request.v1 → warden.source.mutate.response.v1` | internal/server/sourcecontrol_test.go |
| `warden.source.status` | yes | `GET /api/source-control/status` | `source-control status` | `capability:source.read` | `— → warden.source.status.response.v1` | internal/server/sourcecontrol_test.go |
| `warden.terminal-sessions.delete` | yes | `DELETE /api/terminal/sessions` | `terminal-sessions delete` | `capability:terminal.open` | `warden.terminal-sessions.delete.request.v1 → warden.terminal-sessions.delete.response.v1` | internal/server/terminal_sessions_test.go |
| `warden.terminal-sessions.list` | yes | `GET /api/terminal/sessions` | `terminal-sessions list` | `capability:terminal.open` | `— → warden.terminal-sessions.list.response.v1` | internal/server/terminal_sessions_test.go |
| `warden.terminal-sessions.update` | yes | `PUT /api/terminal/sessions` | `terminal-sessions update` | `capability:terminal.open` | `warden.terminal-sessions.update.request.v1 → warden.terminal-sessions.update.response.v1` | internal/server/terminal_sessions_test.go |
| `warden.terminal.open` | yes | `GET /api/terminal` | `—` | `capability:terminal.open` | `— → warden.terminal.open.response.v1` | internal/server/terminal_test.go |
| `warden.users.action` | yes | `POST /api/manage/users/action` | `users action` | `capability:accounts.manage` | `warden.users.action.request.v1 → warden.users.action.response.v1` | internal/server/manage_test.go |
| `warden.users.list` | yes | `GET /api/manage/users` | `users list` | `capability:accounts.manage` | `— → warden.users.list.response.v1` | internal/server/manage_test.go |
| `warden.websites.list` | yes | `GET /api/websites` | `websites list` | `capability:system.read` | `— → warden.websites.list.response.v1` | internal/server/websites_test.go |
| `warden.websites.update` | yes | `POST /api/websites` | `websites update` | `capability:system.read` | `warden.websites.update.request.v1 → warden.websites.update.response.v1` | internal/server/websites_test.go |
| `warden.workspace.replace` | yes | `POST /api/workspace/replace` | `workspace replace` | `capability:workspace.replace` | `warden.workspace.replace.request.v1 → warden.workspace.replace.response.v1` | internal/server/workspace_test.go |
| `warden.workspace.search` | yes | `GET /api/workspace/search` | `workspace search` | `capability:workspace.search` | `— → warden.workspace.search.response.v1` | internal/server/workspace_test.go |
| `warden.workspace.undo` | yes | `POST /api/workspace/replace/undo` | `workspace undo` | `capability:workspace.replace` | `warden.workspace.undo.request.v1 → warden.workspace.undo.response.v1` | internal/server/workspace_test.go |
