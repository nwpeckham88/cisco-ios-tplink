# TP-Link CLI (Go)

This folder contains a ready-to-run Linux AMD64 build of the TP-Link switch CLI.

## Contents

- tplink-cli: compiled command-line binary
- README.md: this guide
- LICENSE: project license

## Quick Start

1. Make sure the binary is executable:

   chmod +x ./tplink-cli

2. Run against your switch:

   ./tplink-cli 192.168.0.1

## Common Usage

- Use explicit credentials:

  ./tplink-cli 192.168.0.1 --user admin --password your-password

- Host can come before or after flags:

  ./tplink-cli --user admin 192.168.0.1

## Password Inputs (priority order)

1. --password
2. --password-stdin
3. --password-file
4. --password-env (defaults to TPLINK_PASSWORD)
5. built-in firmware default

## Notes

- The target switch management plane is HTTP-only.
- Keep this binary in a trusted environment.
