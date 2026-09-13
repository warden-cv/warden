# Warden automation

Example session workflow:

```sh
printf '%s\n' '{"email":"admin@example.invalid","password":"REDACTED"}' > /tmp/warden-login.json
chmod 600 /tmp/warden-login.json
# Choose the login command from the generated matrix, then persist the returned session:
warden <login-resource> <login-verb> --input /tmp/warden-login.json --session-file "$HOME/.config/warden/session.json" --json
```

For subsequent operations use JSON input/stdin, `--json`, bounded `--timeout`, pagination/filter `--query`, and a stable `--request-id`. When an operation declares idempotency support, the request ID is also sent as the idempotency key. Destructive commands require `--yes`. Distributed commands report partial failure instead of collapsing it into success.

See [`CLI.md`](CLI.md) and the generated matrix for exact commands.
