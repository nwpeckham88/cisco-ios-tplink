package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/nwpeckham88/cisco-ios-tplink/tplink"
)

const trunkPort = 8

var vlans = map[int]int{5: 5, 6: 6, 7: 7}

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

	if err := configure(client); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if err := verify(client); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("All checks passed.")
}

func configure(client *tplink.Client) error {
	fmt.Println("Enabling 802.1Q VLAN mode...")
	if err := client.SetDot1QEnabled(true); err != nil {
		return err
	}
	keys := make([]int, 0, len(vlans))
	for vid := range vlans {
		keys = append(keys, vid)
	}
	sort.Ints(keys)
	for _, vid := range keys {
		access := vlans[vid]
		fmt.Printf("  Adding VLAN %d: port %d untagged, port %d tagged\n", vid, access, trunkPort)
		if err := client.AddDot1QVLAN(vid, "", []int{trunkPort}, []int{access}); err != nil {
			return err
		}
	}
	for _, vid := range keys {
		access := vlans[vid]
		fmt.Printf("  Setting port %d PVID -> %d\n", access, vid)
		if err := client.SetPVID([]int{access}, vid); err != nil {
			return err
		}
	}
	return nil
}

func verify(client *tplink.Client) error {
	fmt.Println("\nReading back configuration...")
	enabled, vlanEntries, err := client.GetDot1QVLANS()
	if err != nil {
		return err
	}
	if !enabled {
		return fmt.Errorf("FAIL 802.1Q mode is not enabled")
	}
	vmap := map[int]tplink.Dot1QVlanEntry{}
	for _, v := range vlanEntries {
		vmap[v.VID] = v
	}
	keys := make([]int, 0, len(vlans))
	for vid := range vlans {
		keys = append(keys, vid)
	}
	sort.Ints(keys)
	for _, vid := range keys {
		access := vlans[vid]
		entry, ok := vmap[vid]
		if !ok {
			return fmt.Errorf("FAIL VLAN %d not found", vid)
		}
		tagged := tplink.BitsToPorts(entry.TaggedMembers, 8)
		untagged := tplink.BitsToPorts(entry.UntaggedMembers, 8)
		if len(tagged) != 1 || tagged[0] != trunkPort {
			return fmt.Errorf("FAIL VLAN %d tagged mismatch: %v", vid, tagged)
		}
		if len(untagged) != 1 || untagged[0] != access {
			return fmt.Errorf("FAIL VLAN %d untagged mismatch: %v", vid, untagged)
		}
		fmt.Printf("PASS VLAN %d: tagged=%v untagged=%v\n", vid, tagged, untagged)
	}
	pvids, err := client.GetPVIDs()
	if err != nil {
		return err
	}
	for _, vid := range keys {
		access := vlans[vid]
		actual := -1
		if access <= len(pvids) {
			actual = pvids[access-1]
		}
		if actual != vid {
			return fmt.Errorf("FAIL Port %d PVID expected=%d actual=%d", access, vid, actual)
		}
		fmt.Printf("PASS Port %d PVID=%d\n", access, vid)
	}
	return nil
}

func envOrDefault(key, fallback string) string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return v
}
