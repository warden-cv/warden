# Supply-chain and release controls

Warden's server has one direct third-party Go dependency:
`modernc.org/sqlite`. Its transitive graph is recorded by `go.mod` and `go.sum`;
`scripts/dependency-inventory.sh` produces the exact resolved list for review.
The browser application has no npm dependency graph or runtime CDN dependency.

The release workflow grants read-only repository access by default and grants
`contents: write` only to its release job. Official checkout and Go setup actions
are pinned to reviewed commits. Artifact upload uses the GitHub runner's `gh`
client instead of another JavaScript action.

`scripts/build-release.sh` cross-builds six CGO-free targets from one source
checkout, applies `-trimpath`, stamps the release version, verifies that the local
build path is absent, creates one archive per target and emits SHA-256 checksums.
The embedded Nift output is part of every binary.

`scripts/git-history-hygiene.sh` inspects every reachable Git blob and rejects
compiled executable magic, binary/archive extensions and blobs over 20 MiB. Build
artifacts live only in ignored `dist/` and are removed after local verification.
