package tplink

import (
	"fmt"
	"net/url"
	"strconv"
)

func (c *Client) GetPortSettings() ([]PortInfo, error) {
	html, err := c.page("PortSettingRpm")
	if err != nil {
		return nil, err
	}
	n := asInt(extractVar(html, "max_port_num"))
	if n <= 0 {
		n = 8
	}
	ai := asMap(extractVar(html, "all_info"))
	if len(ai) == 0 {
		return nil, fmt.Errorf("could not parse PortSettingRpm.htm")
	}

	states := getListValue(ai, "state")
	spdCfg := getListValue(ai, "spd_cfg")
	spdAct := getListValue(ai, "spd_act")
	fcCfg := getListValue(ai, "fc_cfg")
	fcAct := getListValue(ai, "fc_act")
	trunk := getListValue(ai, "trunk_info")

	ports := make([]PortInfo, 0, n)
	for i := 0; i < n; i++ {
		cfg := oneBasedIndex(spdCfg, i)
		act := oneBasedIndex(spdAct, i)
		var cfgPtr *PortSpeed
		var actPtr *PortSpeed
		if cfg >= int(PortSpeedAuto) && cfg <= int(PortSpeedM1000F) {
			cfgSpeed := PortSpeed(cfg)
			cfgPtr = &cfgSpeed
		}
		if act >= int(PortSpeedAuto) && act <= int(PortSpeedM1000F) {
			actSpeed := PortSpeed(act)
			actPtr = &actSpeed
		}
		ports = append(ports, PortInfo{
			Port:     i + 1,
			Enabled:  asBool(oneAt(states, i)),
			SpeedCfg: cfgPtr,
			SpeedAct: actPtr,
			FCCfg:    asBool(oneAt(fcCfg, i)),
			FCAct:    asBool(oneAt(fcAct, i)),
			TrunkID:  asInt(oneAt(trunk, i)),
		})
	}
	return ports, nil
}

func (c *Client) SetPort(port int, enabled *bool, speed *PortSpeed, flowControl *bool) error {
	if err := c.validatePort(port, 0); err != nil {
		return err
	}
	return c.SetPorts([]int{port}, enabled, speed, flowControl)
}

func (c *Client) SetPorts(ports []int, enabled *bool, speed *PortSpeed, flowControl *bool) error {
	validatedPorts, err := c.validatePorts(ports, false, 0)
	if err != nil {
		return err
	}
	if speed != nil {
		if *speed < PortSpeedAuto || *speed > PortSpeedM1000F {
			return fmt.Errorf("invalid speed value: %d", *speed)
		}
	}

	params := url.Values{}
	for _, p := range validatedPorts {
		params.Add("portid", strconv.Itoa(p))
	}
	params.Add("state", selectNoChangeBool(enabled))
	params.Add("speed", selectNoChangeSpeed(speed))
	params.Add("flowcontrol", selectNoChangeBool(flowControl))
	_, err = c.cfgGet("port_setting.cgi", params)
	return err
}

func selectNoChangeBool(v *bool) string {
	if v == nil {
		return "7"
	}
	if *v {
		return "1"
	}
	return "0"
}

func selectNoChangeSpeed(speed *PortSpeed) string {
	if speed == nil {
		return "7"
	}
	return strconv.Itoa(int(*speed))
}

func (c *Client) GetPortStatistics() ([]PortStats, error) {
	html, err := c.page("PortStatisticsRpm")
	if err != nil {
		return nil, err
	}
	n := asInt(extractVar(html, "max_port_num"))
	if n <= 0 {
		n = 8
	}
	ai := asMap(extractVar(html, "all_info"))
	if len(ai) == 0 {
		return nil, fmt.Errorf("could not parse PortStatisticsRpm.htm")
	}
	pkts := getListValue(ai, "pkts")
	stats := make([]PortStats, 0, n)
	for i := 0; i < n; i++ {
		tx := oneBasedIndex(pkts, i*2)
		rx := oneBasedIndex(pkts, i*2+1)
		stats = append(stats, PortStats{Port: i + 1, TXPkts: tx, RXPkts: rx})
	}
	return stats, nil
}

func (c *Client) ResetPortStatistics(port *int) error {
	params := url.Values{}
	params.Set("op", "1")
	if port != nil {
		if err := c.validatePort(*port, 0); err != nil {
			return err
		}
		params.Set("portid", strconv.Itoa(*port))
	}
	_, err := c.cfgGet("port_statistics_set.cgi", params)
	return err
}

func (c *Client) GetPortMirror() (MirrorConfig, error) {
	html, err := c.page("PortMirrorRpm")
	if err != nil {
		return MirrorConfig{}, err
	}
	enabled := asBool(extractVar(html, "MirrEn"))
	dest := asInt(extractVar(html, "MirrPort"))
	mode := asInt(extractVar(html, "MirrMode"))
	mi := asMap(extractVar(html, "mirr_info"))
	n := asInt(extractVar(html, "max_port_num"))
	if n <= 0 {
		n = 8
	}
	ingressRaw := getListValue(mi, "ingress")
	egressRaw := getListValue(mi, "egress")
	ingress := make([]int, 0)
	egress := make([]int, 0)
	for i := 0; i < n; i++ {
		if oneBasedIndex(ingressRaw, i) != 0 {
			ingress = append(ingress, i+1)
		}
		if oneBasedIndex(egressRaw, i) != 0 {
			egress = append(egress, i+1)
		}
	}
	return MirrorConfig{Enabled: enabled, DestPort: dest, Mode: mode, IngressPorts: ingress, EgressPorts: egress}, nil
}

func (c *Client) SetPortMirror(enabled bool, destPort *int, ingressPorts []int, egressPorts []int) error {
	ingress, err := c.validatePorts(ingressPorts, true, 0)
	if err != nil {
		return err
	}
	egress, err := c.validatePorts(egressPorts, true, 0)
	if err != nil {
		return err
	}

	if enabled {
		if destPort == nil {
			return fmt.Errorf("dest_port is required when enabled=true")
		}
		if err := c.validatePort(*destPort, 0); err != nil {
			return err
		}
		params := url.Values{}
		params.Set("state", "1")
		params.Set("mirroringport", strconv.Itoa(*destPort))
		params.Set("mirrorenable", "Apply")
		if _, err := c.cfgGet("mirror_enabled_set.cgi", params); err != nil {
			return err
		}

		ingSet := map[int]struct{}{}
		egrSet := map[int]struct{}{}
		for _, p := range ingress {
			ingSet[p] = struct{}{}
		}
		for _, p := range egress {
			egrSet[p] = struct{}{}
		}
		all := map[int]struct{}{}
		for p := range ingSet {
			all[p] = struct{}{}
		}
		for p := range egrSet {
			all[p] = struct{}{}
		}
		for p := range all {
			params := url.Values{}
			params.Set("mirroredport", strconv.Itoa(p))
			if _, ok := ingSet[p]; ok {
				params.Set("ingressState", "1")
			} else {
				params.Set("ingressState", "0")
			}
			if _, ok := egrSet[p]; ok {
				params.Set("egressState", "1")
			} else {
				params.Set("egressState", "0")
			}
			params.Set("mirrored_submit", "Apply")
			if _, err := c.cfgGet("mirrored_port_set.cgi", params); err != nil {
				return err
			}
		}
		return nil
	}
	params := url.Values{}
	params.Set("state", "0")
	params.Set("mirrorenable", "Apply")
	_, err = c.cfgGet("mirror_enabled_set.cgi", params)
	return err
}

func (c *Client) GetPortTrunk() (TrunkConfig, error) {
	html, err := c.page("PortTrunkRpm")
	if err != nil {
		return TrunkConfig{}, err
	}
	tc := asMap(extractVar(html, "trunk_conf"))
	if len(tc) == 0 {
		return TrunkConfig{}, fmt.Errorf("could not parse PortTrunkRpm.htm")
	}
	maxGroups := asInt(tc["maxTrunkNum"])
	if maxGroups <= 0 {
		maxGroups = 2
	}
	portCount := asInt(tc["portNum"])
	if portCount <= 0 {
		portCount = 8
	}
	groups := map[int][]int{}
	for g := 1; g <= maxGroups; g++ {
		raw := getListValue(tc, fmt.Sprintf("portStr_g%d", g))
		members := make([]int, 0)
		for i := 0; i < portCount && i < len(raw); i++ {
			if asInt(raw[i]) != 0 {
				members = append(members, i+1)
			}
		}
		if len(members) > 0 {
			groups[g] = members
		}
	}
	return TrunkConfig{MaxGroups: maxGroups, PortCount: portCount, Groups: groups}, nil
}

func (c *Client) SetPortTrunk(groupID int, ports []int) error {
	if groupID != 1 && groupID != 2 {
		return fmt.Errorf("group_id must be 1 or 2: %d", groupID)
	}
	validatedPorts, err := c.validatePorts(ports, true, 0)
	if err != nil {
		return err
	}

	if len(validatedPorts) > 0 {
		params := url.Values{}
		params.Add("groupId", strconv.Itoa(groupID))
		params.Add("setapply", "Apply")
		for _, p := range validatedPorts {
			params.Add("portid", strconv.Itoa(p))
		}
		_, err = c.cfgGet("port_trunk_set.cgi", params)
		return err
	}
	params := url.Values{}
	params.Set("chk_trunk", strconv.Itoa(groupID))
	params.Set("setDelete", "Delete")
	_, err = c.cfgGet("port_trunk_display.cgi", params)
	return err
}

func (c *Client) GetIGMPSnooping() (IGMPConfig, error) {
	html, err := c.page("IgmpSnoopingRpm")
	if err != nil {
		return IGMPConfig{}, err
	}
	ds := asMap(extractVar(html, "igmp_ds"))
	if len(ds) == 0 {
		return IGMPConfig{}, fmt.Errorf("could not parse IgmpSnoopingRpm.htm")
	}
	return IGMPConfig{
		Enabled:           asBool(ds["state"]),
		ReportSuppression: asBool(ds["suppressionState"]),
		GroupCount:        asInt(ds["count"]),
	}, nil
}

func (c *Client) SetIGMPSnooping(enabled bool, reportSuppression bool) error {
	params := url.Values{}
	if enabled {
		params.Set("igmp_mode", "1")
	} else {
		params.Set("igmp_mode", "0")
	}
	if reportSuppression {
		params.Set("reportSu_mode", "1")
	} else {
		params.Set("reportSu_mode", "0")
	}
	_, err := c.cfgGet("igmpSnooping.cgi", params)
	return err
}

func (c *Client) GetLoopPrevention() (bool, error) {
	html, err := c.page("LoopPreventionRpm")
	if err != nil {
		return false, err
	}
	return asBool(extractVar(html, "lpEn")), nil
}

func (c *Client) SetLoopPrevention(enabled bool) error {
	params := url.Values{}
	if enabled {
		params.Set("lpEn", "1")
	} else {
		params.Set("lpEn", "0")
	}
	_, err := c.cfgGet("loop_prevention_set.cgi", params)
	return err
}
