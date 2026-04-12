# tplink-tool

A Python SDK and interactive CLI for the **TP-Link TL-SG108E** managed
switch — no browser required.

The switch has no REST API, no SSH, and no serial console.  This project
reverse-engineers its HTTP web UI to provide a clean Python interface and a
Cisco IOS-inspired shell.

Developed and tested on:
- Hardware: TL-SG108E v6.0
- Firmware: 1.0.0 Build 20230218 Rel.50633

A full test suite passes against this hardware.  Adjacent firmware revisions
are likely compatible.  Other TP-Link managed switches that share the same
web UI may also work, though this has not been tested.

## Files

| File | Purpose |
|---|---|
| `tplink_tool/sdk.py` | Python SDK (`Switch` class, all read/write operations) |
| `tplink_tool/cli.py` | Interactive CLI (Cisco IOS-style) |
| `examples/` | Practical scripts for VLAN config and read-only smoke tests |
| `docs/sdk.md` | SDK programmer reference |
| `docs/cli.md` | CLI user guide |

## Requirements

```bash
pip install -e .
```

Optional for OS keychain support in CLI:

```bash
pip install -e .[keychain]
```

## Quick start — SDK

```python
from tplink_tool.sdk import Switch, PortSpeed

with Switch('192.168.0.1', password='admin') as sw:
    # Read system info
    print(sw.get_system_info())

    # Port status
    for port in sw.get_port_settings():
        print(port)

    # Configure a port
    sw.set_port(1, speed=PortSpeed.AUTO, flow_control=False)

    # 802.1Q VLANs
    sw.set_dot1q_enabled(True)
    sw.add_dot1q_vlan(10, name='servers', tagged_ports=[8], untagged_ports=[1])
    sw.set_pvid([1], 10)
```

See [docs/sdk.md](docs/sdk.md) for the full API reference.

## Quick start — CLI

```bash
python3 -m tplink_tool.cli 192.168.0.1
```

## Examples

```bash
python3 examples/read_switch.py
python3 examples/configure_vlans.py
```

```
TL-SG108E# show interfaces
TL-SG108E# configure terminal
TL-SG108E(config)# vlan 10
TL-SG108E(config-vlan-10)# name servers
TL-SG108E(config-vlan-10)# exit
TL-SG108E(config)# interface port 1
TL-SG108E(config-if-gi1)# switchport access vlan 10
TL-SG108E(config-if-gi1)# exit
TL-SG108E(config)# end
TL-SG108E# show vlan
```

Commands can be abbreviated to their shortest unambiguous prefix (`conf t`,
`sh int`, `sw acc vl 10`, etc.).

See [docs/cli.md](docs/cli.md) for the full command reference.

## What is supported

### Read operations
- System info (firmware, MAC, IP)
- IP settings
- LED state
- Port settings (speed, duplex, flow control, trunk membership)
- Port statistics (TX/RX packet counters)
- Port mirroring
- Port trunking / LAG
- IGMP snooping
- Loop prevention
- MTU VLAN
- Port-based VLAN
- 802.1Q VLAN (membership, PVIDs)
- QoS (mode, per-port priority)
- Bandwidth control (ingress/egress rate limiting)
- Storm control
- Cable diagnostics (TDR)

### Write operations
Everything listed above, plus:
- Config backup and restore
- Factory reset
- Reboot
- Password change

## Protocol notes

The switch uses a frameset-based HTTP UI on port 80.

- **Reads**: `GET /<Page>.htm` — state is embedded as JavaScript variable
  declarations in the first `<script>` block.
- **Writes**: `GET /<name>.cgi?param=value` — all configuration writes are
  GET requests with query-string parameters (not POST).
- **Session**: cookie-based (`H_P_SSID`, TTL 600 s).  The SDK re-authenticates
  transparently before expiry and after mode-change operations that restart
  the switch's web server.

## Security constraints and mitigations

The TL-SG108E web UI is HTTP-only on current firmware and uses firmware-defined
authentication behavior that cannot be changed from this tool.  This project
therefore focuses on safer local handling and stronger input validation.

Recommended deployment practices:

- Isolate switch management on a dedicated management VLAN.
- Restrict management access to trusted admin hosts only.
- Avoid passing password overrides in CLI argv when possible.
- Use OS keychain storage (`--save-keychain`) for local password persistence.
- Use the built-in firmware password default, or override via `TPLINK_PASSWORD`, keychain, stdin, or password file.
- Rotate shared credentials regularly.

## License

[GNU General Public License v3.0](LICENSE)
