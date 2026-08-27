# Resource limits

Warden treats limits as part of its security contract. This inventory records
the server-side ceilings verified during BH14. Browser controls are convenience,
not enforcement.

| Boundary | Limit |
| --- | ---: |
| Outer HTTP request body | 64 MiB |
| HTTP request headers | 1 MiB |
| File write body | 8 MiB |
| Secure backup import | 4 MiB |
| Conversation mutation | 16 MiB |
| Git combined output | 4 MiB |
| Typed administration input/output | 1 MiB each |
| Terminal WebSocket frame | 64 KiB |
| Terminal scrollback | 256 KiB |
| Durable terminals per account | 16 |
| Browser sessions per account | 32 |
| Pending OAuth states | 128 |
| Agent session export | 8 MiB |
| Workspace replace undo state | 32 MiB |
| Audit event detail | 4 KiB |
| Audit retention | 100,000 events |

The database pool uses at most eight open and four idle connections. Git and
typed system commands have operation deadlines. PTY disconnect kills the process
group. Archive extraction separately limits entry count, expanded bytes and
expansion ratio before publishing any output.

BH14 includes six retained native fuzz targets for domain/upstream validation,
agent session identifiers, audit redaction, Git status parsing and cron syntax.
The checkpoint gate ran each seed corpus under ordinary tests and ran selected
targets for two seconds. These bounded runs are regression evidence, not a claim
that all possible inputs have been exhausted.
