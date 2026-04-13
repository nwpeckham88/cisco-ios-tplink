package tplink

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

type CLIMode string

const (
	ModeExec       CLIMode = "exec"
	ModeConfig     CLIMode = "config"
	ModeConfigIF   CLIMode = "config-if"
	ModeConfigVLAN CLIMode = "config-vlan"
)

type CLI struct {
	client   *Client
	hostname string
	mode     CLIMode
	ifPorts  []int
	vlanID   int
}

func NewCLI(client *Client, hostname string) *CLI {
	if hostname == "" {
		hostname = "switch"
	}
	return &CLI{client: client, hostname: hostname, mode: ModeExec}
}

func (c *CLI) prompt() string {
	switch c.mode {
	case ModeExec:
		return fmt.Sprintf("%s# ", c.hostname)
	case ModeConfig:
		return fmt.Sprintf("%s(config)# ", c.hostname)
	case ModeConfigIF:
		return fmt.Sprintf("%s(config-if-%s)# ", c.hostname, portRangeString(c.ifPorts))
	case ModeConfigVLAN:
		return fmt.Sprintf("%s(config-vlan-%d)# ", c.hostname, c.vlanID)
	default:
		return fmt.Sprintf("%s# ", c.hostname)
	}
}

func (c *CLI) Run() error {
	s := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print(c.prompt())
		if !s.Scan() {
			fmt.Println()
			return nil
		}
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "!") {
			continue
		}
		quit, err := c.execLine(line)
		if err != nil {
			fmt.Printf("  %% %v\n", err)
		}
		if quit {
			return nil
		}
	}
}

func (c *CLI) execLine(line string) (bool, error) {
	handled, err := c.handleQuestion(line)
	if handled {
		return false, err
	}
	if strings.HasPrefix(strings.ToLower(line), "no ") {
		return false, c.handleNo(strings.TrimSpace(line[3:]))
	}
	if strings.HasPrefix(strings.ToLower(line), "do ") {
		saved := c.mode
		c.mode = ModeExec
		quit, err := c.execLine(strings.TrimSpace(line[3:]))
		c.mode = saved
		return quit, err
	}
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return false, nil
	}
	cmd, err := resolveKeyword(parts[0], commandKeywordsForMode(c.mode, false))
	if err != nil {
		return false, err
	}
	args := ""
	if len(parts) > 1 {
		args = strings.Join(parts[1:], " ")
	}

	switch cmd {
	case "exit":
		return c.cmdExit(), nil
	case "quit":
		return true, nil
	case "end":
		c.mode = ModeExec
		return false, nil
	case "help":
		c.cmdHelp()
		return false, nil
	case "configure":
		return false, c.cmdConfigure(args)
	case "interface":
		return false, c.cmdInterface(args)
	case "vlan":
		return false, c.cmdVLAN(args)
	case "name":
		return false, c.cmdVLANName(args)
	case "shutdown":
		return false, c.cmdShutdown()
	case "speed":
		return false, c.cmdSpeed(args)
	case "flowcontrol":
		return false, c.cmdFlowControl(true)
	case "switchport":
		return false, c.cmdSwitchport(args)
	case "channel-group":
		return false, c.cmdChannelGroup(args)
	case "hostname":
		return false, c.cmdHostname(args)
	case "ip":
		return false, c.cmdIP(args)
	case "spanning-tree":
		return false, c.cmdSpanningTree(true)
	case "igmp":
		return false, c.cmdIGMP(args)
	case "led":
		return false, c.cmdLED(true)
	case "username":
		return false, c.cmdUsername(args)
	case "qos":
		return false, c.cmdQoS(args)
	case "bandwidth":
		return false, c.cmdBandwidth(args)
	case "storm-control":
		return false, c.cmdStormControl(args)
	case "monitor":
		return false, c.cmdMonitor(args)
	case "mtu-vlan":
		return false, c.cmdMTUVLAN(args)
	case "port-vlan":
		return false, c.cmdPortVLAN(args)
	case "reload":
		return c.cmdReload(), nil
	case "clear":
		return false, c.cmdClear(args)
	case "test":
		return false, c.cmdTest(args)
	case "copy":
		return c.cmdCopy(args)
	case "write":
		return c.cmdWrite(args)
	case "show":
		return false, c.cmdShow(args)
	default:
		return false, fmt.Errorf("unknown command: %q", cmd)
	}
}

func (c *CLI) handleNo(args string) error {
	parts := strings.Fields(args)
	if len(parts) == 0 {
		return fmt.Errorf("incomplete command")
	}
	cmd, err := resolveKeyword(parts[0], commandKeywordsForMode(c.mode, true))
	if err != nil {
		return err
	}
	rest := ""
	if len(parts) > 1 {
		rest = strings.Join(parts[1:], " ")
	}
	if cmd == "shutdown" {
		if c.mode != ModeConfigIF {
			return fmt.Errorf("command not available in %s mode", c.mode)
		}
		on := true
		return c.client.SetPorts(c.ifPorts, &on, nil, nil)
	}
	if cmd == "flowcontrol" {
		return c.cmdFlowControl(false)
	}
	if cmd == "channel-group" {
		return c.cmdNoChannelGroup(rest)
	}
	if cmd == "vlan" {
		return c.cmdNoVLAN(rest)
	}
	if cmd == "ip" {
		return c.cmdNoIP(rest)
	}
	if cmd == "spanning-tree" {
		return c.cmdSpanningTree(false)
	}
	if cmd == "igmp" {
		return c.cmdNoIGMP(rest)
	}
	if cmd == "led" {
		return c.cmdLED(false)
	}
	if cmd == "bandwidth" {
		return c.cmdNoBandwidth(rest)
	}
	if cmd == "storm-control" {
		return c.cmdNoStormControl()
	}
	if cmd == "monitor" {
		return c.cmdNoMonitor(rest)
	}
	if cmd == "mtu-vlan" {
		return c.cmdNoMTUVLAN()
	}
	if cmd == "port-vlan" {
		return c.cmdNoPortVLAN(rest)
	}
	return fmt.Errorf("no-form for %q is not supported", cmd)
}

func (c *CLI) cmdExit() bool {
	switch c.mode {
	case ModeConfigIF, ModeConfigVLAN:
		c.mode = ModeConfig
		return false
	case ModeConfig:
		c.mode = ModeExec
		return false
	default:
		return true
	}
}

func (c *CLI) cmdHelp() {
	fmt.Printf("\nMode: %s\n", c.mode)
	fmt.Println("Available commands:")
	for _, entry := range helpEntriesForMode(c.mode) {
		fmt.Printf("  %-50s %s\n", entry.syntax, entry.description)
	}
	fmt.Println()
	fmt.Println("Tips:")
	if c.mode == ModeExec {
		fmt.Println("  - Shortest unique prefixes are accepted (for example: conf t, sh ver).")
	} else {
		fmt.Println("  - Shortest unique prefixes are accepted (for example: sh int br, sw acc vlan 10).")
	}
	fmt.Println("  - Use '?' for command completion/help (for example: sh ?, interface ?).")
	if c.mode != ModeExec {
		fmt.Println("  - Use 'do <exec-command>' from configuration modes.")
	}
	fmt.Println()
}

type helpEntry struct {
	syntax      string
	description string
}

func helpEntriesForMode(mode CLIMode) []helpEntry {
	common := []helpEntry{
		{syntax: "help | ?", description: "Show contextual help"},
		{syntax: "exit", description: "Leave current mode (or disconnect from exec mode)"},
		{syntax: "end", description: "Return directly to exec mode"},
		{syntax: "quit", description: "Disconnect immediately"},
	}

	switch mode {
	case ModeExec:
		return append(common,
			helpEntry{syntax: "show <subcommand>", description: "Display switch status and configuration"},
			helpEntry{syntax: "configure terminal", description: "Enter global configuration mode (alias: conf t)"},
			helpEntry{syntax: "clear counters [gi<N>]", description: "Clear all counters or a single interface counter"},
			helpEntry{syntax: "test cable-diagnostics [interface gi<N>]", description: "Run cable diagnostics"},
			helpEntry{syntax: "copy running-config <file>", description: "Backup running config to file"},
			helpEntry{syntax: "copy <file> running-config", description: "Restore config from file and reboot"},
			helpEntry{syntax: "write erase", description: "Factory reset switch and reboot"},
			helpEntry{syntax: "reload", description: "Reboot switch"},
		)
	case ModeConfig:
		return append(common,
			helpEntry{syntax: "show <subcommand>", description: "Display switch status and configuration"},
			helpEntry{syntax: "interface [range] gi<N>[,gi<M>|gi<N>-<M>]", description: "Enter interface configuration mode"},
			helpEntry{syntax: "vlan <1-4094>", description: "Enter VLAN configuration mode"},
			helpEntry{syntax: "no vlan <id>", description: "Delete VLAN from 802.1Q table"},
			helpEntry{syntax: "hostname <name>", description: "Set device description/hostname"},
			helpEntry{syntax: "ip address dhcp", description: "Enable DHCP addressing"},
			helpEntry{syntax: "ip address <ip> <mask>", description: "Set static IP and netmask"},
			helpEntry{syntax: "ip default-gateway <ip>", description: "Set default gateway"},
			helpEntry{syntax: "no ip address dhcp", description: "Disable DHCP and keep current static values"},
			helpEntry{syntax: "spanning-tree | no spanning-tree", description: "Enable/disable loop prevention"},
			helpEntry{syntax: "igmp snooping [report-suppression]", description: "Enable IGMP snooping"},
			helpEntry{syntax: "no igmp snooping", description: "Disable IGMP snooping"},
			helpEntry{syntax: "led | no led", description: "Enable/disable front-panel LEDs"},
			helpEntry{syntax: "username admin password <old> <new>", description: "Change admin password"},
			helpEntry{syntax: "qos mode {port-based|dot1p|dscp}", description: "Set global QoS mode"},
			helpEntry{syntax: "monitor session 1 destination interface gi<N>", description: "Set mirror destination"},
			helpEntry{syntax: "monitor session 1 source interface gi<N> [rx|tx|both]", description: "Add mirror source"},
			helpEntry{syntax: "no monitor", description: "Disable port mirroring"},
			helpEntry{syntax: "mtu-vlan uplink gi<N> | no mtu-vlan", description: "Enable/disable MTU VLAN"},
			helpEntry{syntax: "port-vlan mode enable | no port-vlan mode", description: "Enable/disable port-based VLAN mode"},
			helpEntry{syntax: "port-vlan <id> members gi<N>[,gi<M>]", description: "Create/modify port-based VLAN"},
			helpEntry{syntax: "no port-vlan <id>", description: "Delete port-based VLAN"},
			helpEntry{syntax: "do show <subcommand>", description: "Run exec show command from config mode"},
		)
	case ModeConfigIF:
		return append(common,
			helpEntry{syntax: "show <subcommand>", description: "Display switch status and configuration"},
			helpEntry{syntax: "shutdown | no shutdown", description: "Disable/enable selected interfaces"},
			helpEntry{syntax: "speed {auto|10|100|1000} [half|full]", description: "Set interface speed/duplex"},
			helpEntry{syntax: "flowcontrol | no flowcontrol", description: "Enable/disable flow control"},
			helpEntry{syntax: "switchport access vlan <id>", description: "Set access VLAN"},
			helpEntry{syntax: "switchport trunk allowed vlan {add|remove} <id[,range]>", description: "Manage trunk VLAN membership"},
			helpEntry{syntax: "switchport pvid <id>", description: "Set port PVID"},
			helpEntry{syntax: "switchport mode {access|trunk}", description: "Document intended mode (informational)"},
			helpEntry{syntax: "channel-group {1|2} | no channel-group {1|2}", description: "Add/remove from LAG group"},
			helpEntry{syntax: "qos port-priority <1-4>", description: "Set interface QoS priority"},
			helpEntry{syntax: "bandwidth {ingress|egress} <kbps>", description: "Set bandwidth limit"},
			helpEntry{syntax: "no bandwidth [ingress|egress]", description: "Clear bandwidth limits"},
			helpEntry{syntax: "storm-control {broadcast|multicast|unknown-unicast|all} rate <1-12>", description: "Enable storm control"},
			helpEntry{syntax: "no storm-control", description: "Disable storm control"},
			helpEntry{syntax: "do show <subcommand>", description: "Run exec show command from interface mode"},
		)
	case ModeConfigVLAN:
		return append(common,
			helpEntry{syntax: "show <subcommand>", description: "Display switch status and configuration"},
			helpEntry{syntax: "name <text>", description: "Set VLAN display name"},
			helpEntry{syntax: "do show <subcommand>", description: "Run exec show command from VLAN mode"},
		)
	default:
		return common
	}
}

func (c *CLI) requireMode(modes ...CLIMode) error {
	for _, m := range modes {
		if c.mode == m {
			return nil
		}
	}
	return fmt.Errorf("command not available in %s mode", c.mode)
}

func (c *CLI) cmdConfigure(args string) error {
	if err := c.requireMode(ModeExec); err != nil {
		return err
	}
	parts := strings.Fields(strings.ToLower(args))
	if len(parts) == 0 {
		c.mode = ModeConfig
		return nil
	}
	if len(parts) != 1 {
		return fmt.Errorf("usage: configure terminal")
	}
	sub, err := resolveKeyword(parts[0], []string{"terminal"})
	if err != nil || sub != "terminal" {
		return fmt.Errorf("usage: configure terminal")
	}
	c.mode = ModeConfig
	return nil
}

func (c *CLI) cmdInterface(args string) error {
	if err := c.requireMode(ModeConfig); err != nil {
		return err
	}
	args = strings.TrimSpace(args)
	args = strings.TrimPrefix(strings.ToLower(args), "range ")
	ports := parsePorts(args)
	if len(ports) == 0 {
		return fmt.Errorf("usage: interface port <N> or interface range gi1-3")
	}
	for _, p := range ports {
		if p < 1 || p > 8 {
			return fmt.Errorf("invalid port: %d", p)
		}
	}
	c.ifPorts = ports
	c.mode = ModeConfigIF
	return nil
}

func (c *CLI) cmdVLAN(args string) error {
	if err := c.requireMode(ModeConfig); err != nil {
		return err
	}
	vid, err := strconv.Atoi(strings.TrimSpace(args))
	if err != nil || vid < 1 || vid > 4094 {
		return fmt.Errorf("usage: vlan <1-4094>")
	}
	c.vlanID = vid
	c.mode = ModeConfigVLAN
	return nil
}

func (c *CLI) cmdNoVLAN(args string) error {
	if err := c.requireMode(ModeConfig); err != nil {
		return err
	}
	vid, err := strconv.Atoi(strings.TrimSpace(args))
	if err != nil {
		return fmt.Errorf("usage: no vlan <id>")
	}
	if err := c.client.DeleteDot1QVLAN(vid); err != nil {
		return err
	}
	fmt.Printf("  Deleted VLAN %d\n", vid)
	return nil
}

func (c *CLI) cmdVLANName(name string) error {
	if err := c.requireMode(ModeConfigVLAN); err != nil {
		return err
	}
	name = strings.TrimSpace(name)
	enabled, vlans, err := c.client.GetDot1QVLANS()
	if err != nil {
		return err
	}
	if !enabled {
		if err := c.client.SetDot1QEnabled(true); err != nil {
			return err
		}
		enabled, vlans, err = c.client.GetDot1QVLANS()
		if err != nil {
			return err
		}
		_ = enabled
	}
	tagged := []int{}
	untagged := []int{}
	for _, v := range vlans {
		if v.VID == c.vlanID {
			tagged = BitsToPorts(v.TaggedMembers, 8)
			untagged = BitsToPorts(v.UntaggedMembers, 8)
		}
	}
	return c.client.AddDot1QVLAN(c.vlanID, name, tagged, untagged)
}

func (c *CLI) cmdShutdown() error {
	if err := c.requireMode(ModeConfigIF); err != nil {
		return err
	}
	off := false
	return c.client.SetPorts(c.ifPorts, &off, nil, nil)
}

func (c *CLI) cmdSpeed(args string) error {
	if err := c.requireMode(ModeConfigIF); err != nil {
		return err
	}
	parts := strings.Fields(strings.ToLower(args))
	if len(parts) == 0 {
		return fmt.Errorf("usage: speed {auto|10|100|1000} [half|full]")
	}
	spd := parts[0]
	dup := ""
	if len(parts) > 1 {
		dup = parts[1]
	}
	var speed PortSpeed
	switch {
	case spd == "auto":
		speed = PortSpeedAuto
	case spd == "1000":
		speed = PortSpeedM1000F
	case spd == "100" && (dup == "" || dup == "full"):
		speed = PortSpeedM100F
	case spd == "100" && dup == "half":
		speed = PortSpeedM100H
	case spd == "10" && (dup == "" || dup == "full"):
		speed = PortSpeedM10F
	case spd == "10" && dup == "half":
		speed = PortSpeedM10H
	default:
		return fmt.Errorf("usage: speed {auto|10|100|1000} [half|full]")
	}
	return c.client.SetPorts(c.ifPorts, nil, &speed, nil)
}

func (c *CLI) cmdFlowControl(on bool) error {
	if err := c.requireMode(ModeConfigIF); err != nil {
		return err
	}
	return c.client.SetPorts(c.ifPorts, nil, nil, &on)
}

func (c *CLI) ensureDot1Q() ([]Dot1QVlanEntry, error) {
	enabled, vlans, err := c.client.GetDot1QVLANS()
	if err != nil {
		return nil, err
	}
	if enabled {
		return vlans, nil
	}
	if err := c.client.SetDot1QEnabled(true); err != nil {
		return nil, err
	}
	_, vlans, err = c.client.GetDot1QVLANS()
	return vlans, err
}

func (c *CLI) cmdSwitchport(args string) error {
	if err := c.requireMode(ModeConfigIF); err != nil {
		return err
	}
	parts := strings.Fields(strings.ToLower(args))
	if len(parts) == 0 {
		return fmt.Errorf("usage: switchport {access|trunk|pvid|mode} ...")
	}
	sub, err := resolveKeyword(parts[0], []string{"access", "trunk", "pvid", "mode"})
	if err != nil {
		return err
	}
	switch sub {
	case "pvid":
		if len(parts) < 2 {
			return fmt.Errorf("usage: switchport pvid <id>")
		}
		vid, err := strconv.Atoi(parts[1])
		if err != nil {
			return fmt.Errorf("usage: switchport pvid <id>")
		}
		return c.client.SetPVID(c.ifPorts, vid)
	case "access":
		if len(parts) < 3 || parts[1] != "vlan" {
			return fmt.Errorf("usage: switchport access vlan <id>")
		}
		vid, err := strconv.Atoi(parts[2])
		if err != nil {
			return fmt.Errorf("usage: switchport access vlan <id>")
		}
		vlans, err := c.ensureDot1Q()
		if err != nil {
			return err
		}
		vmap := map[int]Dot1QVlanEntry{}
		for _, v := range vlans {
			vmap[v.VID] = v
		}
		for _, port := range c.ifPorts {
			for _, v := range vlans {
				if v.VID == vid {
					continue
				}
				untagged := BitsToPorts(v.UntaggedMembers, 8)
				if !contains(untagged, port) {
					continue
				}
				untagged = removePort(untagged, port)
				tagged := BitsToPorts(v.TaggedMembers, 8)
				if err := c.client.AddDot1QVLAN(v.VID, v.Name, tagged, untagged); err != nil {
					return err
				}
			}
			v, ok := vmap[vid]
			tagged := []int{}
			untagged := []int{}
			name := ""
			if ok {
				tagged = BitsToPorts(v.TaggedMembers, 8)
				untagged = BitsToPorts(v.UntaggedMembers, 8)
				name = v.Name
			}
			tagged = removePort(tagged, port)
			if !contains(untagged, port) {
				untagged = append(untagged, port)
			}
			if err := c.client.AddDot1QVLAN(vid, name, tagged, untagged); err != nil {
				return err
			}
		}
		return c.client.SetPVID(c.ifPorts, vid)
	case "trunk":
		rest := strings.Join(parts[1:], " ")
		rest = strings.TrimSpace(strings.TrimPrefix(rest, "allowed"))
		rest = strings.TrimSpace(strings.TrimPrefix(rest, "vlan"))
		rp := strings.Fields(rest)
		if len(rp) < 2 {
			return fmt.Errorf("usage: switchport trunk allowed vlan {add|remove} <id[,range]>")
		}
		action := rp[0]
		if action != "add" && action != "remove" {
			return fmt.Errorf("usage: switchport trunk allowed vlan {add|remove} <id[,range]>")
		}
		vids := parseVLANIDs(strings.Join(rp[1:], ""))
		if len(vids) == 0 {
			return fmt.Errorf("usage: switchport trunk allowed vlan {add|remove} <id[,range]>")
		}
		vlans, err := c.ensureDot1Q()
		if err != nil {
			return err
		}
		vmap := map[int]Dot1QVlanEntry{}
		for _, v := range vlans {
			vmap[v.VID] = v
		}
		for _, vid := range vids {
			v, ok := vmap[vid]
			tagged := []int{}
			untagged := []int{}
			name := ""
			if ok {
				tagged = BitsToPorts(v.TaggedMembers, 8)
				untagged = BitsToPorts(v.UntaggedMembers, 8)
				name = v.Name
			}
			for _, port := range c.ifPorts {
				if action == "add" {
					if !contains(tagged, port) {
						tagged = append(tagged, port)
					}
					untagged = removePort(untagged, port)
				} else {
					tagged = removePort(tagged, port)
					untagged = removePort(untagged, port)
				}
			}
			if err := c.client.AddDot1QVLAN(vid, name, tagged, untagged); err != nil {
				return err
			}
		}
		return nil
	case "mode":
		if len(parts) < 2 || (parts[1] != "access" && parts[1] != "trunk") {
			return fmt.Errorf("usage: switchport mode {access|trunk}")
		}
		fmt.Println("  Note: mode is implicit on this switch; membership drives behavior")
		return nil
	default:
		return fmt.Errorf("unknown switchport sub-command: %s", sub)
	}
}

func (c *CLI) cmdChannelGroup(args string) error {
	if err := c.requireMode(ModeConfigIF); err != nil {
		return err
	}
	parts := strings.Fields(args)
	if len(parts) == 0 {
		return fmt.Errorf("usage: channel-group {1|2}")
	}
	gid, err := strconv.Atoi(parts[0])
	if err != nil || (gid != 1 && gid != 2) {
		return fmt.Errorf("usage: channel-group {1|2}")
	}
	tc, err := c.client.GetPortTrunk()
	if err != nil {
		return err
	}
	current := tc.Groups[gid]
	merged := append([]int{}, current...)
	for _, p := range c.ifPorts {
		if !contains(merged, p) {
			merged = append(merged, p)
		}
	}
	sort.Ints(merged)
	return c.client.SetPortTrunk(gid, merged)
}

func (c *CLI) cmdNoChannelGroup(args string) error {
	if err := c.requireMode(ModeConfigIF); err != nil {
		return err
	}
	parts := strings.Fields(args)
	if len(parts) == 0 {
		return fmt.Errorf("usage: no channel-group {1|2}")
	}
	gid, err := strconv.Atoi(parts[0])
	if err != nil || (gid != 1 && gid != 2) {
		return fmt.Errorf("usage: no channel-group {1|2}")
	}
	tc, err := c.client.GetPortTrunk()
	if err != nil {
		return err
	}
	current := tc.Groups[gid]
	updated := make([]int, 0, len(current))
	for _, p := range current {
		if !contains(c.ifPorts, p) {
			updated = append(updated, p)
		}
	}
	return c.client.SetPortTrunk(gid, updated)
}

func (c *CLI) cmdHostname(name string) error {
	if err := c.requireMode(ModeConfig); err != nil {
		return err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("usage: hostname <name>")
	}
	if err := c.client.SetDeviceDescription(name); err != nil {
		return err
	}
	c.hostname = name
	return nil
}

func (c *CLI) cmdIP(args string) error {
	if err := c.requireMode(ModeConfig); err != nil {
		return err
	}
	parts := strings.Fields(strings.ToLower(args))
	if len(parts) == 0 {
		return fmt.Errorf("usage: ip address {<ip> <mask>|dhcp} | ip default-gateway <ip>")
	}
	if parts[0] == "default-gateway" {
		if len(parts) < 2 {
			return fmt.Errorf("usage: ip default-gateway <ip>")
		}
		current, err := c.client.GetIPSettings()
		if err != nil {
			return err
		}
		dhcp := false
		return c.client.SetIPSettings(current.IP, current.Netmask, parts[1], &dhcp)
	}
	if parts[0] == "address" {
		parts = parts[1:]
	}
	if len(parts) == 0 {
		return fmt.Errorf("usage: ip address {<ip> <mask>|dhcp}")
	}
	if parts[0] == "dhcp" {
		dhcp := true
		return c.client.SetIPSettings("", "", "", &dhcp)
	}
	if len(parts) < 2 {
		return fmt.Errorf("usage: ip address <ip> <mask>")
	}
	dhcp := false
	return c.client.SetIPSettings(parts[0], parts[1], "", &dhcp)
}

func (c *CLI) cmdNoIP(args string) error {
	if err := c.requireMode(ModeConfig); err != nil {
		return err
	}
	if !strings.Contains(strings.ToLower(args), "dhcp") {
		return fmt.Errorf("usage: no ip address dhcp")
	}
	current, err := c.client.GetIPSettings()
	if err != nil {
		return err
	}
	dhcp := false
	return c.client.SetIPSettings(current.IP, current.Netmask, current.Gateway, &dhcp)
}

func (c *CLI) cmdSpanningTree(enabled bool) error {
	if err := c.requireMode(ModeConfig); err != nil {
		return err
	}
	return c.client.SetLoopPrevention(enabled)
}

func (c *CLI) cmdIGMP(args string) error {
	if err := c.requireMode(ModeConfig); err != nil {
		return err
	}
	parts := strings.Fields(strings.ToLower(args))
	if len(parts) == 0 || parts[0] != "snooping" {
		return fmt.Errorf("usage: igmp snooping [report-suppression]")
	}
	suppression := contains(parts, "report-suppression")
	return c.client.SetIGMPSnooping(true, suppression)
}

func (c *CLI) cmdNoIGMP(_ string) error {
	if err := c.requireMode(ModeConfig); err != nil {
		return err
	}
	return c.client.SetIGMPSnooping(false, false)
}

func (c *CLI) cmdLED(on bool) error {
	if err := c.requireMode(ModeConfig); err != nil {
		return err
	}
	return c.client.SetLED(on)
}

func (c *CLI) cmdUsername(args string) error {
	if err := c.requireMode(ModeConfig); err != nil {
		return err
	}
	parts := strings.Fields(args)
	for len(parts) > 0 && (strings.EqualFold(parts[0], "admin") || strings.EqualFold(parts[0], "password")) {
		parts = parts[1:]
	}
	if len(parts) < 2 {
		return fmt.Errorf("usage: username admin password <old> <new>")
	}
	return c.client.ChangePassword(parts[0], parts[1], "")
}

func (c *CLI) cmdQoS(args string) error {
	parts := strings.Fields(strings.ToLower(args))
	if len(parts) == 0 {
		return fmt.Errorf("usage: qos mode {port-based|dot1p|dscp} | qos port-priority <1-4>")
	}
	if parts[0] == "mode" {
		if err := c.requireMode(ModeConfig); err != nil {
			return err
		}
		if len(parts) < 2 {
			return fmt.Errorf("usage: qos mode {port-based|dot1p|dscp}")
		}
		var mode QoSMode
		switch parts[1] {
		case "port-based", "port":
			mode = QoSModePortBased
		case "dot1p", "802.1p", "dot1":
			mode = QoSModeDot1P
		case "dscp":
			mode = QoSModeDSCP
		default:
			return fmt.Errorf("unknown qos mode")
		}
		return c.client.SetQoSMode(mode)
	}
	if parts[0] == "port-priority" || parts[0] == "priority" || parts[0] == "pri" {
		if err := c.requireMode(ModeConfigIF); err != nil {
			return err
		}
		if len(parts) < 2 {
			return fmt.Errorf("usage: qos port-priority <1-4>")
		}
		pri, err := strconv.Atoi(parts[1])
		if err != nil {
			return fmt.Errorf("priority must be 1-4")
		}
		return c.client.SetPortPriority(c.ifPorts, pri)
	}
	return fmt.Errorf("unknown qos sub-command")
}

func (c *CLI) cmdBandwidth(args string) error {
	if err := c.requireMode(ModeConfigIF); err != nil {
		return err
	}
	parts := strings.Fields(strings.ToLower(args))
	if len(parts) < 2 {
		return fmt.Errorf("usage: bandwidth {ingress|egress} <kbps>")
	}
	dir := parts[0]
	kbps, err := strconv.Atoi(parts[1])
	if err != nil || kbps < 0 {
		return fmt.Errorf("kbps must be non-negative integer")
	}
	bw, err := c.client.GetBandwidthControl()
	if err != nil {
		return err
	}
	bmap := map[int]BandwidthEntry{}
	for _, b := range bw {
		bmap[b.Port] = b
	}
	for _, p := range c.ifPorts {
		current := bmap[p]
		ing := current.IngressRate
		eg := current.EgressRate
		if strings.HasPrefix(dir, "in") {
			ing = kbps
		} else if strings.HasPrefix(dir, "eg") {
			eg = kbps
		} else {
			return fmt.Errorf("direction must be ingress or egress")
		}
		if err := c.client.SetBandwidthControl([]int{p}, ing, eg); err != nil {
			return err
		}
	}
	return nil
}

func (c *CLI) cmdNoBandwidth(args string) error {
	if err := c.requireMode(ModeConfigIF); err != nil {
		return err
	}
	parts := strings.Fields(strings.ToLower(args))
	if len(parts) == 0 {
		for _, p := range c.ifPorts {
			if err := c.client.SetBandwidthControl([]int{p}, 0, 0); err != nil {
				return err
			}
		}
		return nil
	}
	return c.cmdBandwidth(parts[0] + " 0")
}

func (c *CLI) cmdStormControl(args string) error {
	if err := c.requireMode(ModeConfigIF); err != nil {
		return err
	}
	parts := strings.Fields(strings.ToLower(args))
	if len(parts) < 3 || parts[len(parts)-2] != "rate" {
		return fmt.Errorf("usage: storm-control {broadcast|multicast|unknown-unicast|all} rate <1-12>")
	}
	typeStr := parts[0]
	rate, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		return fmt.Errorf("rate must be integer 1-12")
	}
	if _, ok := StormRateKbps[rate]; !ok {
		return fmt.Errorf("rate index must be 1-12")
	}
	stormTypes := []StormType{}
	switch {
	case strings.HasPrefix("broadcast", typeStr):
		stormTypes = []StormType{StormTypeBroadcast}
	case strings.HasPrefix("multicast", typeStr):
		stormTypes = []StormType{StormTypeMulticast}
	case strings.HasPrefix("unknown-unicast", typeStr) || strings.HasPrefix("unknown", typeStr):
		stormTypes = []StormType{StormTypeUnknownUnicast}
	case strings.HasPrefix("all", typeStr):
		stormTypes = AllStormTypes()
	default:
		return fmt.Errorf("invalid storm type")
	}
	return c.client.SetStormControl(c.ifPorts, rate, stormTypes, true)
}

func (c *CLI) cmdNoStormControl() error {
	if err := c.requireMode(ModeConfigIF); err != nil {
		return err
	}
	return c.client.SetStormControl(c.ifPorts, 0, nil, false)
}

func (c *CLI) cmdMonitor(args string) error {
	if err := c.requireMode(ModeConfig); err != nil {
		return err
	}
	parts := strings.Fields(strings.ToLower(args))
	if len(parts) >= 2 && parts[0] == "session" {
		parts = parts[2:]
	}
	if len(parts) == 0 {
		return fmt.Errorf("usage: monitor session 1 {source|destination} interface gi<N> ...")
	}
	sub := parts[0]
	if strings.HasPrefix(sub, "dest") {
		iface := filterTokens(parts[1:], "interface")
		ports := parsePorts(strings.Join(iface, " "))
		if len(ports) != 1 {
			return fmt.Errorf("usage: monitor session 1 destination interface gi<N>")
		}
		m, err := c.client.GetPortMirror()
		if err != nil {
			return err
		}
		dest := ports[0]
		return c.client.SetPortMirror(true, &dest, m.IngressPorts, m.EgressPorts)
	}
	if strings.HasPrefix(sub, "src") || strings.HasPrefix(sub, "sou") {
		direction := "both"
		iface := parts[1:]
		if len(iface) > 0 {
			last := iface[len(iface)-1]
			if last == "rx" || last == "tx" || last == "both" {
				direction = last
				iface = iface[:len(iface)-1]
			}
		}
		iface = filterTokens(iface, "interface")
		ports := parsePorts(strings.Join(iface, " "))
		if len(ports) == 0 {
			return fmt.Errorf("usage: monitor session 1 source interface gi<N> {rx|tx|both}")
		}
		m, err := c.client.GetPortMirror()
		if err != nil {
			return err
		}
		ingress := append([]int{}, m.IngressPorts...)
		egress := append([]int{}, m.EgressPorts...)
		for _, p := range ports {
			if (direction == "rx" || direction == "both") && !contains(ingress, p) {
				ingress = append(ingress, p)
			}
			if (direction == "tx" || direction == "both") && !contains(egress, p) {
				egress = append(egress, p)
			}
		}
		dest := m.DestPort
		if dest == 0 {
			dest = 1
		}
		return c.client.SetPortMirror(true, &dest, ingress, egress)
	}
	return fmt.Errorf("unknown monitor sub-command")
}

func (c *CLI) cmdNoMonitor(_ string) error {
	if err := c.requireMode(ModeConfig); err != nil {
		return err
	}
	dest := 1
	return c.client.SetPortMirror(false, &dest, nil, nil)
}

func (c *CLI) cmdMTUVLAN(args string) error {
	if err := c.requireMode(ModeConfig); err != nil {
		return err
	}
	parts := filterTokens(strings.Fields(strings.ToLower(args)), "uplink", "interface")
	var uplink *int
	if len(parts) > 0 {
		ports := parsePorts(parts[0])
		if len(ports) == 0 {
			return fmt.Errorf("usage: mtu-vlan uplink gi<N>")
		}
		uplink = &ports[0]
	}
	return c.client.SetMTUVlan(true, uplink)
}

func (c *CLI) cmdNoMTUVLAN() error {
	if err := c.requireMode(ModeConfig); err != nil {
		return err
	}
	return c.client.SetMTUVlan(false, nil)
}

func (c *CLI) cmdPortVLAN(args string) error {
	if err := c.requireMode(ModeConfig); err != nil {
		return err
	}
	parts := strings.Fields(strings.ToLower(args))
	if len(parts) == 0 {
		return fmt.Errorf("usage: port-vlan {mode enable|<id> members <ports>}")
	}
	if parts[0] == "mode" {
		return c.client.SetPortVLANEnabled(true)
	}
	vid, err := strconv.Atoi(parts[0])
	if err != nil {
		return fmt.Errorf("usage: port-vlan <id> members <ports>")
	}
	rest := parts[1:]
	if len(rest) > 0 && rest[0] == "members" {
		rest = rest[1:]
	}
	ports := parsePorts(strings.Join(rest, ","))
	if len(ports) == 0 {
		return fmt.Errorf("usage: port-vlan <id> members gi<N>[,gi<M>]")
	}
	return c.client.AddPortVLAN(vid, ports)
}

func (c *CLI) cmdNoPortVLAN(args string) error {
	if err := c.requireMode(ModeConfig); err != nil {
		return err
	}
	parts := strings.Fields(strings.ToLower(args))
	if len(parts) > 0 && parts[0] == "mode" {
		return c.client.SetPortVLANEnabled(false)
	}
	if len(parts) == 0 {
		return fmt.Errorf("usage: no port-vlan <id>")
	}
	vid, err := strconv.Atoi(parts[0])
	if err != nil {
		return fmt.Errorf("usage: no port-vlan <id>")
	}
	return c.client.DeletePortVLAN(vid)
}

func (c *CLI) cmdReload() bool {
	if c.mode != ModeExec {
		fmt.Printf("  %% command not available in %s mode\n", c.mode)
		return false
	}
	if confirm("  Proceed with reload? [y/N] ") {
		_ = c.client.Reboot()
		fmt.Println("  Reloading...")
		return true
	}
	fmt.Println("  Reload cancelled")
	return false
}

func (c *CLI) cmdClear(args string) error {
	if err := c.requireMode(ModeExec); err != nil {
		return err
	}
	parts := strings.Fields(strings.ToLower(args))
	if len(parts) == 0 || !strings.HasPrefix(parts[0], "count") {
		return fmt.Errorf("usage: clear counters [gi<N>]")
	}
	if len(parts) >= 2 {
		ports := parsePorts(parts[1])
		if len(ports) == 0 {
			return fmt.Errorf("invalid port: %s", parts[1])
		}
		p := ports[0]
		return c.client.ResetPortStatistics(&p)
	}
	return c.client.ResetPortStatistics(nil)
}

func (c *CLI) cmdTest(args string) error {
	if err := c.requireMode(ModeExec); err != nil {
		return err
	}
	parts := filterTokens(strings.Fields(strings.ToLower(args)), "cable-diagnostics", "cable-diag", "tdr", "interface", "cable")
	var ports []int
	if len(parts) > 0 {
		ports = parsePorts(strings.Join(parts, ","))
		if len(ports) == 0 {
			return fmt.Errorf("usage: test cable-diagnostics interface gi<N>")
		}
	}
	return c.printCableDiag(ports)
}

func (c *CLI) printCableDiag(ports []int) error {
	fmt.Println("  Running cable diagnostics...")
	results, err := c.client.RunCableDiagnostic(ports)
	if err != nil {
		return err
	}
	fmt.Printf("\n  %-6s  %-16s  Length\n", "Port", "Status")
	fmt.Printf("  %-6s  %-16s  ------\n", "------", "----------------")
	for _, r := range results {
		length := "--"
		if r.LengthM >= 0 {
			length = fmt.Sprintf("%d m", r.LengthM)
		}
		fmt.Printf("  gi%-4d  %-16s  %s\n", r.Port, r.Status, length)
	}
	fmt.Println()
	return nil
}

func (c *CLI) cmdCopy(args string) (bool, error) {
	if err := c.requireMode(ModeExec); err != nil {
		return false, err
	}
	parts := strings.Fields(args)
	if len(parts) < 2 {
		return false, fmt.Errorf("usage: copy running-config <file> | copy <file> running-config")
	}
	src := strings.ToLower(parts[0])
	dst := strings.ToLower(parts[1])
	if src == "running-config" {
		filename := parts[1]
		data, err := c.client.BackupConfig()
		if err != nil {
			return false, err
		}
		if err := os.WriteFile(filename, data, 0o600); err != nil {
			return false, err
		}
		fmt.Printf("  Config saved to %q (%d bytes)\n", filename, len(data))
		return false, nil
	}
	if dst == "running-config" {
		filename := parts[0]
		data, err := os.ReadFile(filename)
		if err != nil {
			return false, err
		}
		if !confirm(fmt.Sprintf("  Restore from %q? This will reboot the switch. [y/N] ", filename)) {
			fmt.Println("  Cancelled")
			return false, nil
		}
		if err := c.client.RestoreConfig(data); err != nil {
			return false, err
		}
		fmt.Println("  Config restored. Switch is rebooting...")
		return true, nil
	}
	return false, fmt.Errorf("usage: copy running-config <file> | copy <file> running-config")
}

func (c *CLI) cmdWrite(args string) (bool, error) {
	if err := c.requireMode(ModeExec); err != nil {
		return false, err
	}
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(args)), "er") {
		return false, fmt.Errorf("usage: write erase")
	}
	if !confirm("  Factory reset? ALL configuration will be lost. [y/N] ") {
		fmt.Println("  Cancelled")
		return false, nil
	}
	if err := c.client.FactoryReset(); err != nil {
		return false, err
	}
	fmt.Println("  Factory reset initiated. Switch is rebooting...")
	return true, nil
}

func (c *CLI) cmdShow(args string) error {
	parts := strings.Fields(strings.ToLower(args))
	if len(parts) == 0 {
		return fmt.Errorf("usage: show <subcommand>")
	}
	sub, err := resolveKeyword(parts[0], showSubcommandKeywords())
	if err != nil {
		return err
	}
	rest := parts[1:]
	switch sub {
	case "version":
		return c.showVersion()
	case "interfaces":
		return c.showInterfaces(rest)
	case "vlan-health":
		return c.showVLANHealth()
	case "vlan":
		return c.showVLAN(rest)
	case "ip":
		return c.showIP()
	case "running-config":
		return c.showRunningConfig()
	case "qos":
		return c.showQoS(rest)
	case "spanning-tree":
		return c.showSpanningTree()
	case "port-mirror":
		return c.showPortMirror()
	case "etherchannel":
		return c.showEtherChannel()
	case "mtu-vlan":
		return c.showMTUVLAN()
	case "cable-diag":
		ports := []int{}
		if len(rest) > 0 {
			ports = parsePorts(rest[0])
		}
		return c.printCableDiag(ports)
	default:
		return fmt.Errorf("unknown show sub-command")
	}
}

func (c *CLI) showVersion() error {
	info, err := c.client.GetSystemInfo()
	if err != nil {
		return err
	}
	ip, err := c.client.GetIPSettings()
	if err != nil {
		return err
	}
	fmt.Printf("\n  %s\n", info.Description)
	fmt.Printf("  Hardware : %s\n", info.Hardware)
	fmt.Printf("  Firmware : %s\n", info.Firmware)
	fmt.Printf("  MAC      : %s\n", info.MAC)
	fmt.Printf("  IP       : %s / %s  (%s)\n", info.IP, info.Netmask, ternary(ip.DHCP, "DHCP", "static"))
	fmt.Printf("  Gateway  : %s\n\n", info.Gateway)
	return nil
}

func (c *CLI) showInterfaces(args []string) error {
	ports, err := c.client.GetPortSettings()
	if err != nil {
		return err
	}
	sub := "brief"
	if len(args) > 0 {
		sub = args[0]
	}
	if sub == "counters" {
		stats, err := c.client.GetPortStatistics()
		if err != nil {
			return err
		}
		smap := map[int]PortStats{}
		for _, s := range stats {
			smap[s.Port] = s
		}
		fmt.Printf("\n  %-6s  %12s  %12s\n", "Port", "TX Pkts", "RX Pkts")
		fmt.Printf("  %-6s  %12s  %12s\n", "------", "----------", "----------")
		for _, p := range ports {
			s := smap[p.Port]
			fmt.Printf("  gi%-4d  %12d  %12d\n", p.Port, s.TXPkts, s.RXPkts)
		}
		fmt.Println()
		return nil
	}
	if sub == "port" && len(args) >= 2 {
		n, err := strconv.Atoi(args[1])
		if err == nil {
			filtered := []PortInfo{}
			for _, p := range ports {
				if p.Port == n {
					filtered = append(filtered, p)
				}
			}
			ports = filtered
		}
	}
	fmt.Printf("\n  %-6s  %-8s  %-12s  %-10s  %-5s  LAG\n", "Port", "Status", "Actual", "Config", "FC")
	fmt.Println("  --------------------------------------------------------")
	for _, p := range ports {
		status := ternary(p.Enabled, "up", "down")
		actual := "--"
		if p.SpeedAct != nil {
			actual = p.SpeedAct.String()
		}
		cfg := "--"
		if p.SpeedCfg != nil {
			cfg = p.SpeedCfg.String()
		}
		fc := ternary(p.FCCfg, "on", "off")
		lag := "--"
		if p.TrunkID > 0 {
			lag = fmt.Sprintf("LAG%d", p.TrunkID)
		}
		fmt.Printf("  gi%-4d  %-8s  %-12s  %-10s  %-5s  %s\n", p.Port, status, actual, cfg, fc, lag)
	}
	fmt.Println()
	return nil
}

func (c *CLI) showVLAN(_ []string) error {
	pvEnabled, pv, err := c.client.GetPortVLAN()
	if err != nil {
		return err
	}
	qEnabled, qv, err := c.client.GetDot1QVLANS()
	if err != nil {
		return err
	}
	if qEnabled {
		pvids, err := c.client.GetPVIDs()
		if err != nil {
			return err
		}
		fmt.Printf("\n  VLAN mode: 802.1Q\n\n")
		fmt.Printf("  %-6s  %-16s  %-20s  %s\n", "VLAN", "Name", "Tagged Ports", "Untagged Ports")
		fmt.Printf("  %-6s  %-16s  %-20s  %s\n", "----", "----------------", "--------------------", "---------------")
		for _, v := range qv {
			t := portRangeString(BitsToPorts(v.TaggedMembers, 8))
			u := portRangeString(BitsToPorts(v.UntaggedMembers, 8))
			fmt.Printf("  %-6d  %-16s  %-20s  %s\n", v.VID, v.Name, t, u)
		}
		fmt.Println()
		fmt.Print("  Port PVIDs:  ")
		for i, p := range pvids {
			if i > 0 {
				fmt.Print("  ")
			}
			fmt.Printf("gi%d:%d", i+1, p)
		}
		fmt.Println()
		return nil
	}
	if pvEnabled {
		fmt.Printf("\n  VLAN mode: port-based\n\n")
		fmt.Printf("  %-6s  %s\n", "VLAN", "Member Ports")
		fmt.Printf("  %-6s  %s\n", "----", "-------------------------")
		for _, v := range pv {
			fmt.Printf("  %-6d  %s\n", v.VID, portRangeString(BitsToPorts(v.Members, 8)))
		}
		fmt.Println()
		return nil
	}
	fmt.Printf("\n  VLAN mode: none\n  No VLAN configuration active.\n\n")
	return nil
}

func (c *CLI) showVLANHealth() error {
	enabled, vlans, err := c.client.GetDot1QVLANS()
	if err != nil {
		return err
	}
	if !enabled {
		fmt.Println()
		fmt.Println("  802.1Q is disabled; no health issues to report.")
		fmt.Println()
		return nil
	}
	pvids, err := c.client.GetPVIDs()
	if err != nil {
		return err
	}
	vlanIDs := map[int]struct{}{}
	untaggedByPort := map[int][]int{}
	for _, v := range vlans {
		vlanIDs[v.VID] = struct{}{}
		for _, p := range BitsToPorts(v.UntaggedMembers, 8) {
			untaggedByPort[p] = append(untaggedByPort[p], v.VID)
		}
	}
	issues := []string{}
	for idx, pvid := range pvids {
		port := idx + 1
		untagged := untaggedByPort[port]
		if len(untagged) > 1 {
			issues = append(issues, fmt.Sprintf("gi%d is untagged on multiple VLANs (%v)", port, untagged))
		}
		if _, ok := vlanIDs[pvid]; !ok {
			issues = append(issues, fmt.Sprintf("gi%d PVID=%d but VLAN %d does not exist", port, pvid, pvid))
			continue
		}
		if !containsInt(untagged, pvid) {
			issues = append(issues, fmt.Sprintf("gi%d PVID=%d but port is not untagged in VLAN %d", port, pvid, pvid))
		}
	}
	if len(issues) == 0 {
		fmt.Println()
		fmt.Println("  No issues found - VLAN configuration is healthy.")
		fmt.Println()
		return nil
	}
	fmt.Printf("\n  %d issue(s) detected:\n\n", len(issues))
	for i, issue := range issues {
		fmt.Printf("  [%d] %s\n", i+1, issue)
	}
	fmt.Println()
	return nil
}

func (c *CLI) showIP() error {
	ip, err := c.client.GetIPSettings()
	if err != nil {
		return err
	}
	fmt.Printf("\n  IP Address : %s\n", ip.IP)
	fmt.Printf("  Subnet Mask: %s\n", ip.Netmask)
	fmt.Printf("  Gateway    : %s\n", ip.Gateway)
	fmt.Printf("  DHCP       : %s\n\n", ternary(ip.DHCP, "enabled", "disabled"))
	return nil
}

func (c *CLI) showRunningConfig() error {
	info, err := c.client.GetSystemInfo()
	if err != nil {
		return err
	}
	ip, err := c.client.GetIPSettings()
	if err != nil {
		return err
	}
	ports, err := c.client.GetPortSettings()
	if err != nil {
		return err
	}
	loop, err := c.client.GetLoopPrevention()
	if err != nil {
		return err
	}
	igmp, err := c.client.GetIGMPSnooping()
	if err != nil {
		return err
	}
	led, err := c.client.GetLED()
	if err != nil {
		return err
	}
	qEnabled, qv, err := c.client.GetDot1QVLANS()
	if err != nil {
		return err
	}
	pvids := []int{}
	if qEnabled {
		pvids, err = c.client.GetPVIDs()
		if err != nil {
			return err
		}
	}
	fmt.Println("!")
	fmt.Printf("hostname %s\n", info.Description)
	fmt.Println("!")
	if ip.DHCP {
		fmt.Println("ip address dhcp")
	} else {
		fmt.Printf("ip address %s %s\n", ip.IP, ip.Netmask)
		fmt.Printf("ip default-gateway %s\n", ip.Gateway)
	}
	fmt.Println("!")
	if loop {
		fmt.Println("spanning-tree")
	}
	if igmp.Enabled {
		if igmp.ReportSuppression {
			fmt.Println("igmp snooping report-suppression")
		} else {
			fmt.Println("igmp snooping")
		}
	}
	if !led {
		fmt.Println("no led")
	}
	fmt.Println("!")
	if qEnabled {
		for _, v := range qv {
			fmt.Printf("vlan %d\n", v.VID)
			if v.Name != "" {
				fmt.Printf(" name %s\n", v.Name)
			}
			fmt.Println("!")
		}
	}
	for _, p := range ports {
		fmt.Printf("interface gi%d\n", p.Port)
		if !p.Enabled {
			fmt.Println(" shutdown")
		}
		if p.SpeedCfg != nil && *p.SpeedCfg != PortSpeedAuto {
			fmt.Printf(" speed %s\n", speedCmdString(*p.SpeedCfg))
		}
		if p.FCCfg {
			fmt.Println(" flowcontrol")
		}
		if p.TrunkID != 0 {
			fmt.Printf(" channel-group %d\n", p.TrunkID)
		}
		if qEnabled && len(pvids) >= p.Port {
			pvid := pvids[p.Port-1]
			for _, v := range qv {
				if v.VID == 1 {
					continue
				}
				u := BitsToPorts(v.UntaggedMembers, 8)
				t := BitsToPorts(v.TaggedMembers, 8)
				if contains(u, p.Port) {
					fmt.Printf(" switchport access vlan %d\n", v.VID)
				} else if contains(t, p.Port) {
					fmt.Printf(" switchport trunk allowed vlan add %d\n", v.VID)
				}
			}
			if pvid != 1 {
				fmt.Printf(" switchport pvid %d\n", pvid)
			}
		}
		fmt.Println("!")
	}
	fmt.Println("end")
	return nil
}

func (c *CLI) showQoS(args []string) error {
	sub := "all"
	if len(args) > 0 {
		sub = args[0]
	}
	mode, qosPorts, err := c.client.GetQoSSettings()
	if err != nil {
		return err
	}
	if sub == "all" || strings.HasPrefix("basic", sub) || strings.HasPrefix("ba", sub) {
		modeStr := "DSCP"
		if mode == QoSModePortBased {
			modeStr = "Port-based"
		} else if mode == QoSModeDot1P {
			modeStr = "802.1p"
		}
		fmt.Printf("\n  QoS mode: %s\n", modeStr)
		fmt.Printf("\n  %-6s  Priority\n", "Port")
		fmt.Printf("  %-6s  --------\n", "------")
		for _, p := range qosPorts {
			fmt.Printf("  gi%-4d  %s\n", p.Port, qosPriorityLabel(p.Priority))
		}
		fmt.Println()
	}
	if sub == "all" || strings.HasPrefix("bandwidth", sub) || strings.HasPrefix("ban", sub) {
		bw, err := c.client.GetBandwidthControl()
		if err != nil {
			return err
		}
		fmt.Printf("  %-6s  %12s  %12s\n", "Port", "Ingress", "Egress")
		fmt.Printf("  %-6s  %12s  %12s\n", "------", "------------", "------------")
		for _, b := range bw {
			ing := "unlimited"
			eg := "unlimited"
			if b.IngressRate > 0 {
				ing = fmt.Sprintf("%d kbps", b.IngressRate)
			}
			if b.EgressRate > 0 {
				eg = fmt.Sprintf("%d kbps", b.EgressRate)
			}
			fmt.Printf("  gi%-4d  %12s  %12s\n", b.Port, ing, eg)
		}
		fmt.Println()
	}
	if sub == "all" || strings.HasPrefix("storm-control", sub) || strings.HasPrefix("storm", sub) || strings.HasPrefix("sto", sub) {
		sc, err := c.client.GetStormControl()
		if err != nil {
			return err
		}
		fmt.Printf("  %-6s  %-8s  Rate idx  Storm Types\n", "Port", "Enabled")
		fmt.Printf("  %-6s  %-8s  --------  -----------\n", "------", "-------")
		for _, s := range sc {
			if s.Enabled {
				types := []string{}
				if s.StormTypes&1 != 0 {
					types = append(types, "UU")
				}
				if s.StormTypes&2 != 0 {
					types = append(types, "MC")
				}
				if s.StormTypes&4 != 0 {
					types = append(types, "BC")
				}
				kbps := StormRateKbps[s.RateIndex]
				fmt.Printf("  gi%-4d  %-8s  %5d kbps  %s\n", s.Port, "yes", kbps, strings.Join(types, ","))
			} else {
				fmt.Printf("  gi%-4d  %-8s  --\n", s.Port, "no")
			}
		}
		fmt.Println()
	}
	return nil
}

func (c *CLI) showSpanningTree() error {
	enabled, err := c.client.GetLoopPrevention()
	if err != nil {
		return err
	}
	fmt.Printf("\n  Loop prevention: %s\n\n", ternary(enabled, "enabled", "disabled"))
	return nil
}

func (c *CLI) showPortMirror() error {
	m, err := c.client.GetPortMirror()
	if err != nil {
		return err
	}
	fmt.Printf("\n  Port mirroring: %s\n", ternary(m.Enabled, "enabled", "disabled"))
	if m.Enabled {
		fmt.Printf("  Destination  : gi%d\n", m.DestPort)
		fmt.Printf("  Ingress src  : %s\n", portRangeString(m.IngressPorts))
		fmt.Printf("  Egress src   : %s\n", portRangeString(m.EgressPorts))
	}
	fmt.Println()
	return nil
}

func (c *CLI) showEtherChannel() error {
	tc, err := c.client.GetPortTrunk()
	if err != nil {
		return err
	}
	fmt.Println()
	if len(tc.Groups) == 0 {
		fmt.Println("  No LAG groups configured.")
		fmt.Println()
		return nil
	}
	keys := make([]int, 0, len(tc.Groups))
	for k := range tc.Groups {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	for _, gid := range keys {
		fmt.Printf("  LAG%d: %s\n", gid, portRangeString(tc.Groups[gid]))
	}
	fmt.Println()
	return nil
}

func (c *CLI) showMTUVLAN() error {
	mv, err := c.client.GetMTUVlan()
	if err != nil {
		return err
	}
	fmt.Printf("\n  MTU VLAN: %s\n", ternary(mv.Enabled, "enabled", "disabled"))
	if mv.Enabled && mv.UplinkPort > 0 {
		fmt.Printf("  Uplink  : gi%d\n", mv.UplinkPort)
	}
	fmt.Println()
	return nil
}

func commandKeywordsForMode(mode CLIMode, noForm bool) []string {
	if noForm {
		switch mode {
		case ModeConfig:
			return []string{"vlan", "ip", "spanning-tree", "igmp", "led", "monitor", "mtu-vlan", "port-vlan"}
		case ModeConfigIF:
			return []string{"shutdown", "flowcontrol", "channel-group", "bandwidth", "storm-control"}
		default:
			return nil
		}
	}

	common := []string{"exit", "quit", "end", "help"}
	switch mode {
	case ModeExec:
		return append(common, "configure", "reload", "clear", "test", "copy", "write", "show")
	case ModeConfig:
		return append(common, "interface", "vlan", "hostname", "ip", "spanning-tree", "igmp", "led", "username", "qos", "monitor", "mtu-vlan", "port-vlan", "show")
	case ModeConfigIF:
		return append(common, "shutdown", "speed", "flowcontrol", "switchport", "channel-group", "qos", "bandwidth", "storm-control", "show")
	case ModeConfigVLAN:
		return append(common, "name", "show")
	default:
		return append(common, "show")
	}
}

func showSubcommandKeywords() []string {
	return []string{
		"version",
		"interfaces",
		"vlan",
		"vlan-health",
		"ip",
		"running-config",
		"qos",
		"spanning-tree",
		"port-mirror",
		"etherchannel",
		"mtu-vlan",
		"cable-diag",
	}
}

func normalizeKeyword(token string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(token)), "_", "-")
}

func uniqueNormalized(options []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(options))
	for _, opt := range options {
		norm := normalizeKeyword(opt)
		if norm == "" {
			continue
		}
		if _, ok := seen[norm]; ok {
			continue
		}
		seen[norm] = struct{}{}
		out = append(out, norm)
	}
	sort.Strings(out)
	return out
}

func prefixMatches(partial string, options []string) []string {
	partial = normalizeKeyword(partial)
	all := uniqueNormalized(options)
	if partial == "" {
		return all
	}
	matches := make([]string, 0, len(all))
	for _, opt := range all {
		if strings.HasPrefix(opt, partial) {
			matches = append(matches, opt)
		}
	}
	return matches
}

func resolveKeyword(token string, options []string) (string, error) {
	token = normalizeKeyword(token)
	if token == "" {
		return "", fmt.Errorf("incomplete command")
	}
	all := uniqueNormalized(options)
	for _, opt := range all {
		if opt == token {
			return opt, nil
		}
	}
	matches := prefixMatches(token, all)
	if len(matches) == 0 {
		return "", fmt.Errorf("unknown command: %q", token)
	}
	if len(matches) > 1 {
		return "", fmt.Errorf("ambiguous command %q (%s)", token, strings.Join(matches, ", "))
	}
	return matches[0], nil
}

func subcommandKeywords(cmd string) []string {
	switch cmd {
	case "configure":
		return []string{"terminal"}
	case "show":
		return showSubcommandKeywords()
	case "switchport":
		return []string{"access", "trunk", "pvid", "mode"}
	case "qos":
		return []string{"mode", "port-priority"}
	case "ip":
		return []string{"address", "default-gateway"}
	case "monitor":
		return []string{"session"}
	case "clear":
		return []string{"counters"}
	case "test":
		return []string{"cable-diagnostics"}
	case "copy":
		return []string{"running-config"}
	case "write":
		return []string{"erase"}
	case "interface":
		return []string{"port", "range"}
	default:
		return nil
	}
}

func showSubcommandChildren(sub string) []string {
	switch sub {
	case "interfaces":
		return []string{"brief", "counters", "port"}
	case "qos":
		return []string{"all", "basic", "bandwidth", "storm-control"}
	default:
		return nil
	}
}

func (c *CLI) completionCandidates(mode CLIMode, noForm bool, tokens []string, partial string) []string {
	cmds := commandKeywordsForMode(mode, noForm)
	if len(tokens) == 0 {
		return prefixMatches(partial, cmds)
	}

	matchedTop := prefixMatches(tokens[0], cmds)
	if len(tokens) == 1 {
		if len(matchedTop) != 1 {
			return matchedTop
		}
		return prefixMatches(partial, subcommandKeywords(matchedTop[0]))
	}

	if len(matchedTop) != 1 {
		return matchedTop
	}
	cmd := matchedTop[0]
	if cmd != "show" {
		return prefixMatches(partial, subcommandKeywords(cmd))
	}

	if len(tokens) == 2 {
		matchedShowSub := prefixMatches(tokens[1], showSubcommandKeywords())
		if len(matchedShowSub) != 1 {
			return matchedShowSub
		}
		return prefixMatches(partial, showSubcommandChildren(matchedShowSub[0]))
	}
	return nil
}

func (c *CLI) handleQuestion(line string) (bool, error) {
	line = strings.TrimSpace(line)
	if !strings.Contains(line, "?") {
		return false, nil
	}
	if strings.Count(line, "?") > 1 || !strings.HasSuffix(line, "?") {
		return true, fmt.Errorf("place ? at the end of the command")
	}

	beforeQ := strings.TrimSuffix(line, "?")
	trailingSpaceBeforeQ := strings.HasSuffix(beforeQ, " ")
	beforeQ = strings.TrimSpace(beforeQ)

	mode := c.mode
	noForm := false
	parts := strings.Fields(beforeQ)
	if len(parts) > 0 && normalizeKeyword(parts[0]) == "do" {
		mode = ModeExec
		if len(parts) > 1 {
			beforeQ = strings.Join(parts[1:], " ")
		} else {
			beforeQ = ""
		}
	}
	parts = strings.Fields(beforeQ)
	if len(parts) > 0 && normalizeKeyword(parts[0]) == "no" {
		noForm = true
		if len(parts) > 1 {
			beforeQ = strings.Join(parts[1:], " ")
		} else {
			beforeQ = ""
		}
	}

	tokens := strings.Fields(beforeQ)
	partial := ""
	if !trailingSpaceBeforeQ && len(tokens) > 0 {
		partial = tokens[len(tokens)-1]
		tokens = tokens[:len(tokens)-1]
	}

	candidates := c.completionCandidates(mode, noForm, tokens, partial)
	fmt.Println()
	if len(candidates) == 0 {
		fmt.Println("  % no matching completions")
		fmt.Println()
		return true, nil
	}
	for _, cand := range candidates {
		fmt.Printf("  %s\n", cand)
	}
	fmt.Println()
	return true, nil
}

func parsePorts(spec string) []int {
	spec = strings.TrimSpace(strings.ToLower(spec))
	if spec == "" {
		return nil
	}
	parseAtom := func(token string) (int, bool) {
		token = strings.TrimSpace(strings.ToLower(token))
		for _, pfx := range []string{"port", "gi", "gigabitethernet", "gige", "ethernet", "eth"} {
			token = strings.TrimSpace(strings.TrimPrefix(token, pfx))
		}
		if token == "" {
			return 0, false
		}
		if strings.Contains(token, "/") {
			parts := strings.Split(token, "/")
			last := parts[len(parts)-1]
			n, err := strconv.Atoi(last)
			return n, err == nil
		}
		n, err := strconv.Atoi(token)
		return n, err == nil
	}
	set := map[int]struct{}{}
	for _, rawPart := range strings.Split(spec, ",") {
		part := strings.TrimSpace(rawPart)
		if part == "" {
			return nil
		}
		if strings.Contains(part, "-") {
			pair := strings.SplitN(part, "-", 2)
			lo, ok1 := parseAtom(pair[0])
			hi, ok2 := parseAtom(pair[1])
			if !ok1 || !ok2 || hi < lo {
				return nil
			}
			for p := lo; p <= hi; p++ {
				set[p] = struct{}{}
			}
			continue
		}
		p, ok := parseAtom(part)
		if !ok {
			return nil
		}
		set[p] = struct{}{}
	}
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

func parseVLANIDs(spec string) []int {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil
	}
	set := map[int]struct{}{}
	for _, raw := range strings.Split(spec, ",") {
		part := strings.TrimSpace(raw)
		if part == "" {
			return nil
		}
		if strings.Contains(part, "-") {
			pair := strings.SplitN(part, "-", 2)
			lo, err1 := strconv.Atoi(pair[0])
			hi, err2 := strconv.Atoi(pair[1])
			if err1 != nil || err2 != nil || lo < 1 || hi > 4094 || hi < lo {
				return nil
			}
			for v := lo; v <= hi; v++ {
				set[v] = struct{}{}
			}
			continue
		}
		v, err := strconv.Atoi(part)
		if err != nil || v < 1 || v > 4094 {
			return nil
		}
		set[v] = struct{}{}
	}
	out := make([]int, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}

func portRangeString(ports []int) string {
	if len(ports) == 0 {
		return "-"
	}
	sorted := append([]int{}, ports...)
	sort.Ints(sorted)
	chunks := []string{}
	start := sorted[0]
	prev := sorted[0]
	for _, p := range sorted[1:] {
		if p == prev+1 {
			prev = p
			continue
		}
		if start == prev {
			chunks = append(chunks, fmt.Sprintf("gi%d", start))
		} else {
			chunks = append(chunks, fmt.Sprintf("gi%d-%d", start, prev))
		}
		start = p
		prev = p
	}
	if start == prev {
		chunks = append(chunks, fmt.Sprintf("gi%d", start))
	} else {
		chunks = append(chunks, fmt.Sprintf("gi%d-%d", start, prev))
	}
	return strings.Join(chunks, ",")
}

func speedCmdString(spd PortSpeed) string {
	switch spd {
	case PortSpeedM10H:
		return "10 half"
	case PortSpeedM10F:
		return "10 full"
	case PortSpeedM100H:
		return "100 half"
	case PortSpeedM100F:
		return "100 full"
	case PortSpeedM1000F:
		return "1000 full"
	default:
		return "auto"
	}
}

func qosPriorityLabel(priority int) string {
	switch priority {
	case 1:
		return "Lowest"
	case 2:
		return "Normal"
	case 3:
		return "Medium"
	case 4:
		return "Highest"
	default:
		return strconv.Itoa(priority)
	}
}

func contains[T comparable](hay []T, needle T) bool {
	for _, v := range hay {
		if v == needle {
			return true
		}
	}
	return false
}

func containsInt(hay []int, needle int) bool {
	for _, v := range hay {
		if v == needle {
			return true
		}
	}
	return false
}

func removePort(ports []int, remove int) []int {
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if p != remove {
			out = append(out, p)
		}
	}
	return out
}

func ternary[T any](cond bool, yes T, no T) T {
	if cond {
		return yes
	}
	return no
}

func confirm(prompt string) bool {
	fmt.Print(prompt)
	r := bufio.NewReader(os.Stdin)
	line, _ := r.ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y"
}

func filterTokens(in []string, drop ...string) []string {
	dropSet := map[string]struct{}{}
	for _, d := range drop {
		dropSet[d] = struct{}{}
	}
	out := make([]string, 0, len(in))
	for _, token := range in {
		if _, ok := dropSet[token]; ok {
			continue
		}
		out = append(out, token)
	}
	return out
}

func ResolvePassword(password string, passwordStdin bool, passwordFile string, passwordEnv string) (string, error) {
	if password != "" {
		fmt.Fprintln(os.Stderr, "warning: --password can leak secrets via process list/shell history; prefer env, stdin, or password file")
		return password, nil
	}
	if passwordStdin {
		r := bufio.NewReader(os.Stdin)
		line, err := r.ReadString('\n')
		if err != nil && !errors.Is(err, os.ErrClosed) {
			line = strings.TrimRight(line, "\r\n")
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			return "", fmt.Errorf("password from stdin is empty")
		}
		return line, nil
	}
	if passwordFile != "" {
		content, err := os.ReadFile(passwordFile)
		if err != nil {
			return "", fmt.Errorf("unable to read password file %q: %w", passwordFile, err)
		}
		line := strings.SplitN(string(content), "\n", 2)[0]
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			return "", fmt.Errorf("password file is empty: %q", passwordFile)
		}
		return line, nil
	}
	if passwordEnv != "" {
		if v := os.Getenv(passwordEnv); v != "" {
			return v, nil
		}
	}
	fmt.Fprintln(os.Stderr, "warning: falling back to built-in firmware password")
	return FirmwarePassword, nil
}
