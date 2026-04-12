package main

import (
	"fmt"
	"os"

	"github.com/nwpeckham88/cisco-ios-tplink/tplink"
)

func main() {
	host := envOrDefault("TPLINK_HOST", "10.1.1.239")
	user := envOrDefault("TPLINK_USER", "admin")
	password := envOrDefault("TPLINK_PASSWORD", tplink.FirmwarePassword)

	client, err := tplink.NewClient(host, tplink.WithUsername(user), tplink.WithPassword(password))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if err := client.Login(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer client.Logout()

	info, err := client.GetSystemInfo()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("System: %s\n", info)

	ip, _ := client.GetIPSettings()
	fmt.Printf("IP: %+v\n", ip)

	ports, _ := client.GetPortSettings()
	fmt.Println("Ports:")
	for _, p := range ports {
		fmt.Printf("  %s\n", p)
	}

	stats, _ := client.GetPortStatistics()
	fmt.Println("Port stats:")
	for _, s := range stats {
		fmt.Printf("  Port %d: TX=%d RX=%d\n", s.Port, s.TXPkts, s.RXPkts)
	}

	fmt.Printf("Loop prevention: %v\n", mustBool(client.GetLoopPrevention()))
	fmt.Printf("Port mirror: %+v\n", mustMirror(client.GetPortMirror()))
	fmt.Printf("Port trunk: %+v\n", mustTrunk(client.GetPortTrunk()))
	fmt.Printf("MTU VLAN: %+v\n", mustMTU(client.GetMTUVlan()))

	qEnabled, qVLANS, _ := client.GetDot1QVLANS()
	fmt.Printf("802.1Q enabled: %v\n", qEnabled)
	for _, v := range qVLANS {
		tagged := tplink.BitsToPorts(v.TaggedMembers, 8)
		untagged := tplink.BitsToPorts(v.UntaggedMembers, 8)
		fmt.Printf("  VLAN %d (%s): tagged=%v untagged=%v\n", v.VID, v.Name, tagged, untagged)
	}

	pvids, _ := client.GetPVIDs()
	fmt.Printf("PVIDs: %v\n", pvids)

	mode, qosPorts, _ := client.GetQoSSettings()
	fmt.Printf("QoS mode: %d\n", mode)
	for _, qp := range qosPorts {
		fmt.Printf("  Port %d priority %d\n", qp.Port, qp.Priority)
	}

	bw, _ := client.GetBandwidthControl()
	fmt.Printf("Bandwidth: %+v\n", bw)

	storm, _ := client.GetStormControl()
	for _, s := range storm {
		if !s.Enabled {
			fmt.Printf("  Port %d storm: disabled\n", s.Port)
			continue
		}
		kbps := tplink.StormRateKbps[s.RateIndex]
		fmt.Printf("  Port %d storm: %d kbps types=%d\n", s.Port, kbps, s.StormTypes)
	}
}

func envOrDefault(key, fallback string) string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return v
}

func mustBool(v bool, err error) bool {
	if err != nil {
		return false
	}
	return v
}

func mustMirror(v tplink.MirrorConfig, err error) tplink.MirrorConfig {
	if err != nil {
		return tplink.MirrorConfig{}
	}
	return v
}

func mustTrunk(v tplink.TrunkConfig, err error) tplink.TrunkConfig {
	if err != nil {
		return tplink.TrunkConfig{}
	}
	return v
}

func mustMTU(v tplink.MTUVlanConfig, err error) tplink.MTUVlanConfig {
	if err != nil {
		return tplink.MTUVlanConfig{}
	}
	return v
}
