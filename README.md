# TL-SG108E Go Rewrite

This folder contains a Go rewrite of the TL-SG108E SDK and CLI.

## What is included

- `tplink/` SDK for TL-SG108E session auth, reads, and writes
- `tplink/cli.go` Cisco IOS-style interactive CLI engine
- `cmd/tplink-cli/` runnable CLI binary
- `examples/read_switch/` read-only smoke example
- `examples/configure_vlans/` VLAN configure and verify example

## Build

```bash
go build ./...
```

## Build release tarball

Create a release directory plus tar.gz package:

```bash
chmod +x scripts/build-release.sh
scripts/build-release.sh
```

This outputs artifacts under `dist/releases/`:

- `dist/releases/tplink-cli-<goos>-<goarch>/`
- `dist/releases/tplink-cli-<goos>-<goarch>.tar.gz`
- `dist/releases/tplink-cli-<goos>-<goarch>.tar.gz.sha256` (when checksum tool is available)

The target folder contains the binary plus `README.md`, `LICENSE`, and `VERSION`.
Each run replaces previous `tplink-cli-*` artifacts so `dist/releases/` stays tidy.

Cross-build example:

```bash
scripts/build-release.sh --goos linux --goarch arm64 --version v1.2.3
```

For GitHub releases, see `.github/workflows/release.yml`, which calls the same script and uploads artifacts on `v*` tags.

## Run CLI

```bash
go run ./cmd/tplink-cli 192.168.0.1
```

Flags can be provided before or after host:

```bash
go run ./cmd/tplink-cli 192.168.0.1 --user admin
go run ./cmd/tplink-cli --user admin 192.168.0.1
```

Interactive completion (TTY mode):

- Press `?` to show context-aware command help immediately (no Enter required)
- Press `Tab` to complete commands using shortest unique matches

Cisco IOS compatibility highlights:

- `write memory` (also `wr mem`) to save configuration (IOS-style alias)
- `copy running-config startup-config` to save configuration (IOS-style alias)
- `erase startup-config` (alias for `write erase`) for factory reset flow
- `show startup-config` (mapped to `show running-config` on this platform)
- `show interfaces status` (alias to interface brief/status view)
- `interface range gi1-4` enters `config-if-range` style mode

When stdin is not a terminal (for example piped input), the CLI uses line-based input behavior.

Optional auth flags:

```bash
go run ./cmd/tplink-cli 192.168.0.1 --user admin --password secret
```

Run a native CLI command file non-interactively:

```bash
go run ./cmd/tplink-cli 192.168.0.1 --config-file examples/iac/v1-static.cfg
```

The config file can use the same Cisco-style commands you would type in the interactive CLI. See [examples/iac/v1-static.cfg](examples/iac/v1-static.cfg) and [examples/iac/v1-dhcp.cfg](examples/iac/v1-dhcp.cfg).

`--password` is supported for compatibility but less secure than env/stdin/file.

Password source precedence:

1. `--password`
2. `--password-stdin`
3. `--password-file`
4. `--password-env` (default `TPLINK_PASSWORD`)
5. built-in firmware default (`testpass`)

## Run examples

```bash
go run ./examples/read_switch
go run ./examples/configure_vlans
```

## Test

```bash
go test ./...
```
