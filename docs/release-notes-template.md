# Warden {{VERSION}}

Warden {{VERSION}} is a {{RELEASE_KIND}}.

## What this release is

- One self-hosted Go executable with an embedded dashboard.
- A browser-based server administration and coding-agent surface: system
  administration pages, the Warden Agent and editor agent panel, sessions and
  authenticated, audited mutations.
- Checksum-verified release archives for Linux, macOS and Windows on amd64 and
  arm64, plus `checksums.txt`.

## Operator responsibilities

- Warden's authenticated sessions are intentionally privileged; read the
  security guidance before exposing Warden to the Internet.
- Back up before upgrading.
- Warden is a public preview for evaluation and early self-hosting; it is not
  claimed to be production-proven or battle-proven.

## Installation

- https://warden.cv/install.sh (per-user)
- https://warden.cv/download.sh (download the archive)
- https://warden.cv/update.sh (upgrade an existing install)