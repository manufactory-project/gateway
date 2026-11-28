# Contributing to gateway

This file covers changing the code. To install and run `gateway`, see the [README](README.md).

Today `task check` and CI accept commits only from the project's bot identity, so a pull request with commits under your own name fails. See [Commits](#commits).

## Set up

Develop on Linux. CI runs on Ubuntu 24.04 with these tools:

| Tool | Version | Used for |
|---|---|---|
| Go | 1.26.11 (set by `GOTOOLCHAIN` in the Taskfile) | build and test |
| [Task](https://taskfile.dev) | 3.54.0 | running checks |
| golangci-lint | 2.12.2 | `task lint` |
| ShellCheck | 0.11.0 | `e2e/run.sh` |

The race detector used by the tests also needs a C compiler.

## Check a change

```bash
task check
```

This runs `task lint`, then `task test` (`go test -race -count=1 ./...`).

If you changed `e2e/run.sh`, also run what CI runs on it:

```bash
bash -n e2e/run.sh
shellcheck -S warning e2e/run.sh
```

## End-to-end test

Run this when a change touches networking, `netsetup`, the systemd units or the probe. It needs a standalone (not clustered) Incus host, Go, Python 3 and OpenSSL. By default it also expects:

- a local Incus network named `incusbr0` and a storage pool named `default`
- port 443 on the host to be free and reachable from the gateway container; the script uses `sudo` for the local upstream, so run `sudo -v` first if you are not root
- something listening on port 22 at that network's host address, used as the LAN target (or pass `--lan-addr`)
- ports 22 and 853 at that address: if nothing answers, the script starts its own listener, with `sudo` if you are not root
- an interactive terminal, to confirm before it creates anything

Print the Incus commands without creating anything:

```bash
./e2e/run.sh --project gateway-e2e --plan-only
```

Run it:

```bash
task e2e -- --project gateway-e2e
```

The script refuses to use an existing project, asks before creating one, and deletes it on exit unless you pass `--keep`. `./e2e/run.sh --help` lists the options, including flags that break the wiring on purpose to show that the probe catches it.

## Rules that lint enforces

- `gofmt` reports no files.
- `govulncheck` finds no known vulnerabilities in reachable code.
- Every directory with tests calls `goleak.VerifyTestMain`.
- `//nolint:errcheck` is not allowed. Handle the error; `errcheck` also rejects discarding it with `_`.
- Any other `nolint` directive names its linter and explains why.
- Outside tests, functions stay within 120 lines, 80 statements and cognitive complexity 40.
- `deadcode` finds no unreachable functions.
- `internal/admin` does not depend on `proxy`, `secret`, `policy` or `netguard`.
- `cmd/gateway-probe` uses only the standard library.
- Go files do not contain `NOW.md:` references.
- `go mod tidy -diff` reports no changes.

[Taskfile.yml](Taskfile.yml) and [.golangci.yml](.golangci.yml) are the source of truth.

## Commits

`task lint` checks the identity on every non-merge commit in the history. The author must be `Manufactory Bot <bot@manufactory.systems>`, and the committer must be that bot or `GitHub <noreply@github.com>`. A commit under any other identity fails CI.

Existing subjects follow `type(scope): summary`, for example `fix(proxy): bound WebSocket upstream handshake`.

## Keep the docs true

Update these in the same change as the behavior they describe:

- [README.md](README.md) for commands and install steps
- [docs/configuration.md](docs/configuration.md) for config keys, defaults, rule precedence and reload
- [docs/architecture.md](docs/architecture.md) for process, request path and package changes
- [docs/threat-model.md](docs/threat-model.md) for any change to what is blocked, allowed or accepted as a risk
- [examples/](examples/) for config schema changes

Never commit real keys, certificates or secret values. `.gitignore` excludes `*.key`, `*.pem`, `*.crt` and `.env` files.
