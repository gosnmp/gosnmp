# AGENTS.md

gosnmp is a Go SNMP library (v1, v2c, v3/USM): client, trap listener and trap sender. [GLOSSARY.md](GLOSSARY.md) lists where Go names differ from SNMP terms.

## Testing

Most tests sit behind build tags, so use the Makefile rather than a plain `go test ./...`. See also "Running the Tests" in the README.

- `make test`: each tag group in turn, plus the `netsnmp/` module. Most `end2end` tests skip unless `GOSNMP_TARGET` and `GOSNMP_PORT` point at an SNMP agent.
- `make test-race`: `-tags all -race`, as CI runs it on amd64; this is the only target that runs the `walk` tests.
- `make net-snmp-test`: tests against live net-snmp; needs `libsnmp-dev`.
- Tag a new test file `//go:build all || <area>`.
- On macOS, `TestUnconnectedSocket_success` and `TestGenericFailureConnectionRefused` fail because of platform socket behaviour; CI runs on Linux.

## Rules

- Don't rename, remove or change the signature of exported identifiers, struct fields or the `Handler` interface. Code must build with the `go` version in `go.mod` and on 386.
- Don't hand-edit generated files. `make generate` installs the tools and regenerates the stringer `*_string.go` files (CI fails on a diff). After changing `Handler`, regenerate `mocks/gosnmp_mock.go` with `mockgen --source interface.go --destination mocks/gosnmp_mock.go --package mocks`.
- `marshal.go`, `helper.go`, `v3*.go` and `trap.go` parse untrusted network input: bounds-check every length and never panic on a malformed packet.
- Never log or return passphrases, keys or community strings. `UsmSecurityParameters.SafeString()` omits passphrases and keys; `Description()` includes them, and `SnmpPacket.SafeString()` includes the community.
- Sign off commits (`git commit -s`); the DCO check fails without it.

## Agent skills

Optional settings for agent skills, such as [mattpocock/skills](https://github.com/mattpocock/skills), that read them. If you don't use such skills, ignore this section.

### Issue tracker

GitHub Issues on gosnmp/gosnmp, via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Triage roles mapped to this repo's labels (`needs-info` is `incomplete`). See `docs/agents/triage-labels.md`.

### Domain docs

Domain terms are in `GLOSSARY.md` at the repo root; there is no `docs/adr/` yet. See `docs/agents/domain.md`.
