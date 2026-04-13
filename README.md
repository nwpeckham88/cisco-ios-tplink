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

When stdin is not a terminal (for example piped input), the CLI uses line-based input behavior.

Optional auth flags:

```bash
go run ./cmd/tplink-cli 192.168.0.1 --user admin --password secret
```

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
