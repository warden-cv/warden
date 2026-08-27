# Warden threat model

Warden is a privileged self-hosted process. The browser, reverse proxy, remote
clients, filenames, repository content, terminal streams, model/provider output
and imported configuration are hostile inputs. SQLite, the private configuration
directory and the operating-system account running Warden are trusted only to
the extent documented by deployment guidance.

The application-account boundary controls Warden capabilities and ownership. It
does not create an operating-system sandbox. Terminal and agent subprocesses
inherit the Warden process user's authority.

Every `/api` route is registered through `apiRoutes` with exactly one boundary:
public bootstrap/authentication, authenticated session, named capability, or
authenticated/capability/origin/CSRF WebSocket. Tests reject duplicate,
unclassified and capability-less authoritative routes.

The campaign risk register begins with these retained limits:

- terminal and agent isolation requires OS users or stronger containment;
- local audit data is attributable but not tamper-proof;
- Google availability and identity assertions depend on the provider;
- filesystem confinement must continue to defend against platform-specific
  links, races and special files;
- Warden remains a development build until BH17 closes the campaign.
