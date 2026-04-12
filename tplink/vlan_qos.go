package tplink

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

func (c *Client) GetMTUVlan() (MTUVlanConfig, error) {
	html, err := c.page("VlanMtuRpm")
	if err != nil {
		return MTUVlanConfig{}, err
	}
	ds := asMap(extractVar(html, "mtu_ds"))
	if len(ds) == 0 {
		return MTUVlanConfig{}, fmt.Errorf("could not parse VlanMtuRpm.htm")
	}
	pc := asInt(ds["portNum"])
	if pc <= 0 {
		pc = 8
	}
	uplink := asInt(ds["uplinkPort"])
	if uplink <= 0 {
		uplink = 1
	}
	return MTUVlanConfig{Enabled: asBool(ds["state"]), PortCount: pc, UplinkPort: uplink}, nil
}

func (c *Client) SetMTUVlan(enabled bool, uplinkPort *int) error {
	if uplinkPort != nil {
		if err := c.validatePort(*uplinkPort, 0); err != nil {
			return err
		}
	}
	current, err := c.GetMTUVlan()
	if err != nil {
		return err
	}
	up := current.UplinkPort
	if uplinkPort != nil {
		up = *uplinkPort
	}
	params := url.Values{}
	if enabled {
		params.Set("mtu_en", "1")
	} else {
		params.Set("mtu_en", "0")
	}
	params.Set("uplinkPort", strconv.Itoa(up))
	_, err = c.cfgGet("mtuVlanSet.cgi", params)
	return err
}

func (c *Client) GetPortVLAN() (bool, []PortVlanEntry, error) {
	html, err := c.page("VlanPortBasicRpm")
	if err != nil {
		return false, nil, err
	}
	ds := asMap(extractVar(html, "pvlan_ds"))
	if len(ds) == 0 {
		return false, nil, fmt.Errorf("could not parse VlanPortBasicRpm.htm")
	}
	enabled := asBool(ds["state"])
	count := asInt(ds["count"])
	vids := getListValue(ds, "vids")
	mbrs := getListValue(ds, "mbrs")
	entries := make([]PortVlanEntry, 0, count)
	for i := 0; i < count; i++ {
		entries = append(entries, PortVlanEntry{VID: oneBasedIndex(vids, i), Members: oneBasedIndex(mbrs, i)})
	}
	return enabled, entries, nil
}

func (c *Client) SetPortVLANEnabled(enabled bool) error {
	params := url.Values{}
	if enabled {
		params.Set("pvlan_en", "1")
	} else {
		params.Set("pvlan_en", "0")
	}
	params.Set("pvlan_mode", "Apply")
	_, err := c.cfgGet("pvlanSet.cgi", params)
	return err
}

func (c *Client) AddPortVLAN(vid int, memberPorts []int) error {
	if err := validateVLANID(vid, "vid"); err != nil {
		return err
	}
	validatedPorts, err := c.validatePorts(memberPorts, false, 0)
	if err != nil {
		return err
	}
	params := url.Values{}
	params.Add("vid", strconv.Itoa(vid))
	params.Add("pvlan_add", "Apply")
	for _, p := range validatedPorts {
		params.Add("selPorts", strconv.Itoa(p))
	}
	_, err = c.cfgGet("pvlanSet.cgi", params)
	return err
}

func (c *Client) DeletePortVLAN(vid int) error {
	if err := validateVLANID(vid, "vid"); err != nil {
		return err
	}
	params := url.Values{}
	params.Set("selVlans", strconv.Itoa(vid))
	params.Set("pvlan_del", "Delete")
	_, err := c.cfgGet("pvlanSet.cgi", params)
	return err
}

func (c *Client) GetDot1QVLANS() (bool, []Dot1QVlanEntry, error) {
	html, err := c.page("Vlan8021QRpm")
	if err != nil {
		return false, nil, err
	}
	ds := asMap(extractVar(html, "qvlan_ds"))
	if len(ds) == 0 {
		return false, nil, fmt.Errorf("could not parse Vlan8021QRpm.htm")
	}
	enabled := asBool(ds["state"])
	count := asInt(ds["count"])
	vids := getListValue(ds, "vids")
	names := getListValue(ds, "names")
	tagMbrs := getListValue(ds, "tagMbrs")
	untagMbrs := getListValue(ds, "untagMbrs")

	entries := make([]Dot1QVlanEntry, 0, count)
	for i := 0; i < count; i++ {
		entries = append(entries, Dot1QVlanEntry{
			VID:             oneBasedIndex(vids, i),
			Name:            asString(oneAt(names, i)),
			TaggedMembers:   oneBasedIndex(tagMbrs, i),
			UntaggedMembers: oneBasedIndex(untagMbrs, i),
		})
	}
	return enabled, entries, nil
}

func (c *Client) SetDot1QEnabled(enabled bool) error {
	params := url.Values{}
	if enabled {
		params.Set("qvlan_en", "1")
	} else {
		params.Set("qvlan_en", "0")
	}
	params.Set("qvlan_mode", "Apply")
	_, err := c.cfgGet("qvlanSet.cgi", params)
	return err
}

func (c *Client) AddDot1QVLAN(vid int, name string, taggedPorts []int, untaggedPorts []int) error {
	if err := validateVLANID(vid, "vid"); err != nil {
		return err
	}
	tagged, err := c.validatePorts(taggedPorts, true, 0)
	if err != nil {
		return err
	}
	untagged, err := c.validatePorts(untaggedPorts, true, 0)
	if err != nil {
		return err
	}
	taggedSet := map[int]struct{}{}
	untaggedSet := map[int]struct{}{}
	for _, p := range tagged {
		taggedSet[p] = struct{}{}
	}
	for _, p := range untagged {
		if _, ok := taggedSet[p]; ok {
			return fmt.Errorf("tagged_ports and untagged_ports overlap: [%d]", p)
		}
		untaggedSet[p] = struct{}{}
	}

	params := url.Values{}
	params.Set("vid", strconv.Itoa(vid))
	params.Set("vname", name)
	params.Set("qvlan_add", "Add/Modify")
	for i := 1; i <= c.portCount; i++ {
		if _, ok := taggedSet[i]; ok {
			params.Set(fmt.Sprintf("selType_%d", i), "1")
			continue
		}
		if _, ok := untaggedSet[i]; ok {
			params.Set(fmt.Sprintf("selType_%d", i), "0")
			continue
		}
		params.Set(fmt.Sprintf("selType_%d", i), "2")
	}
	_, err = c.cfgGet("qvlanSet.cgi", params)
	return err
}

func (c *Client) DeleteDot1QVLAN(vid int) error {
	if err := validateVLANID(vid, "vid"); err != nil {
		return err
	}
	params := url.Values{}
	params.Set("selVlans", strconv.Itoa(vid))
	params.Set("qvlan_del", "Delete")
	_, err := c.cfgGet("qvlanSet.cgi", params)
	return err
}

func (c *Client) GetPVIDs() ([]int, error) {
	html, err := c.page("Vlan8021QPvidRpm")
	if err != nil {
		return nil, err
	}
	ds := asMap(extractVar(html, "pvid_ds"))
	if len(ds) == 0 {
		return nil, fmt.Errorf("could not parse Vlan8021QPvidRpm.htm")
	}
	raw := getListValue(ds, "pvids")
	out := make([]int, len(raw))
	for i := range raw {
		out[i] = asInt(raw[i])
	}
	return out, nil
}

func (c *Client) SetPVID(ports []int, pvid int) error {
	validatedPorts, err := c.validatePorts(ports, false, 0)
	if err != nil {
		return err
	}
	if err := validateVLANID(pvid, "pvid"); err != nil {
		return err
	}
	params := url.Values{}
	params.Set("pbm", strconv.Itoa(PortsToBits(validatedPorts)))
	params.Set("pvid", strconv.Itoa(pvid))
	_, err = c.cfgGet("vlanPvidSet.cgi", params)
	return err
}

func (c *Client) GetQoSSettings() (QoSMode, []QoSPortConfig, error) {
	html, err := c.page("QosBasicRpm")
	if err != nil {
		return QoSModeDSCP, nil, err
	}
	rawMode := asInt(extractVar(html, "qosMode"))
	mode := QoSMode(rawMode)
	if rawMode < 0 || rawMode > 2 {
		mode = QoSModeDSCP
	}
	n := asInt(extractVar(html, "portNumber"))
	if n <= 0 {
		n = 8
	}
	pPri := asSlice(extractVar(html, "pPri"))
	ports := make([]QoSPortConfig, 0, n)
	for i := 0; i < n; i++ {
		ports = append(ports, QoSPortConfig{Port: i + 1, Priority: oneBasedIndex(pPri, i)})
	}
	return mode, ports, nil
}

func (c *Client) SetQoSMode(mode QoSMode) error {
	form := url.Values{}
	form.Set("rd_qosmode", strconv.Itoa(int(mode)))
	form.Set("qosmode", "Apply")
	_, err := c.cfgPost("qos_mode_set.cgi", form)
	return err
}

func (c *Client) SetPortPriority(ports []int, priority int) error {
	validatedPorts, err := c.validatePorts(ports, false, 0)
	if err != nil {
		return err
	}
	if err := validateQoSPriority(priority); err != nil {
		return err
	}
	form := url.Values{}
	form.Set("port_queue", strconv.Itoa(priority-1))
	form.Set("apply", "Apply")
	for _, p := range validatedPorts {
		form.Set(fmt.Sprintf("sel_%d", p), "1")
	}
	_, err = c.cfgPost("qos_port_priority_set.cgi", form)
	return err
}

func (c *Client) GetBandwidthControl() ([]BandwidthEntry, error) {
	html, err := c.page("QosBandWidthControlRpm")
	if err != nil {
		return nil, err
	}
	n := asInt(extractVar(html, "portNumber"))
	if n <= 0 {
		n = 8
	}
	bc := asSlice(extractVar(html, "bcInfo"))
	entries := make([]BandwidthEntry, 0, n)
	for i := 0; i < n; i++ {
		base := i * 3
		entries = append(entries, BandwidthEntry{
			Port:        i + 1,
			IngressRate: oneBasedIndex(bc, base),
			EgressRate:  oneBasedIndex(bc, base+1),
		})
	}
	return entries, nil
}

func (c *Client) SetBandwidthControl(ports []int, ingressKbps int, egressKbps int) error {
	validatedPorts, err := c.validatePorts(ports, false, 0)
	if err != nil {
		return err
	}
	if err := validateBandwidthRate(ingressKbps, "ingress_kbps"); err != nil {
		return err
	}
	if err := validateBandwidthRate(egressKbps, "egress_kbps"); err != nil {
		return err
	}
	form := url.Values{}
	form.Set("igrRate", strconv.Itoa(ingressKbps))
	form.Set("egrRate", strconv.Itoa(egressKbps))
	form.Set("applay", "Apply")
	for _, p := range validatedPorts {
		form.Set(fmt.Sprintf("sel_%d", p), "1")
	}
	_, err = c.cfgPost("qos_bandwidth_set.cgi", form)
	return err
}

func (c *Client) GetStormControl() ([]StormEntry, error) {
	html, err := c.page("QosStormControlRpm")
	if err != nil {
		return nil, err
	}
	n := asInt(extractVar(html, "portNumber"))
	if n <= 0 {
		n = 8
	}
	sc := asSlice(extractVar(html, "scInfo"))
	entries := make([]StormEntry, 0, n)
	for i := 0; i < n; i++ {
		base := i * 3
		entries = append(entries, StormEntry{
			Port:       i + 1,
			Enabled:    oneBasedIndex(sc, base+2) != 0,
			RateIndex:  oneBasedIndex(sc, base),
			StormTypes: oneBasedIndex(sc, base+1),
		})
	}
	return entries, nil
}

func (c *Client) SetStormControl(ports []int, rateIndex int, stormTypes []StormType, enabled bool) error {
	validatedPorts, err := c.validatePorts(ports, false, 0)
	if err != nil {
		return err
	}
	if len(stormTypes) == 0 {
		stormTypes = AllStormTypes()
	}
	if enabled {
		if err := validateStormRateIndex(rateIndex); err != nil {
			return err
		}
	}

	form := url.Values{}
	if enabled {
		form.Add("state", "1")
	} else {
		form.Add("state", "0")
	}
	form.Add("applay", "Apply")
	if enabled {
		form.Add("rate", strconv.Itoa(rateIndex))
		for _, st := range stormTypes {
			if st != StormTypeUnknownUnicast && st != StormTypeMulticast && st != StormTypeBroadcast {
				return fmt.Errorf("invalid storm type: %d", st)
			}
			form.Add("stormType", strconv.Itoa(int(st)))
		}
	}
	for _, p := range validatedPorts {
		form.Add(fmt.Sprintf("sel_%d", p), "1")
	}
	_, err = c.cfgPost("qos_storm_set.cgi", form)
	return err
}

func (c *Client) RunCableDiagnostic(ports []int) ([]CableDiagResult, error) {
	html, err := c.page("CableDiagRpm")
	if err != nil {
		return nil, err
	}
	maxPort := asInt(extractVar(html, "maxPort"))
	if maxPort <= 0 {
		maxPort = 8
	}
	if len(ports) == 0 {
		ports = make([]int, 0, maxPort)
		for i := 1; i <= maxPort; i++ {
			ports = append(ports, i)
		}
	} else {
		ports, err = c.validatePorts(ports, false, maxPort)
		if err != nil {
			return nil, err
		}
	}

	results := make([]CableDiagResult, 0, len(ports))
	for _, p := range ports {
		form := url.Values{}
		form.Set("portid", strconv.Itoa(p))
		body, err := c.cfgPost("cable_diag_get.cgi", form)
		if err != nil {
			return nil, err
		}
		if body == nil {
			return nil, fmt.Errorf("cable diagnostic request was interrupted; retry the operation")
		}
		state := asSlice(extractVar(string(body), "cablestate"))
		length := asSlice(extractVar(string(body), "cablelength"))
		idx := p - 1
		rawState := -1
		rawLength := -1
		if idx >= 0 && idx < len(state) {
			rawState = asInt(state[idx])
		}
		if idx >= 0 && idx < len(length) {
			rawLength = asInt(length[idx])
		}
		statusMap := map[int]string{0: "OK", 1: "Short", 2: "Open", 3: "Unknown", -1: "Unknown"}
		status, ok := statusMap[rawState]
		if !ok {
			status = "Unknown"
		}
		results = append(results, CableDiagResult{Port: p, Status: status, LengthM: rawLength})
	}
	return results, nil
}

func boolPtr(v bool) *bool { return &v }
func intPtr(v int) *int    { return &v }
func speedPtr(v PortSpeed) *PortSpeed {
	vv := v
	return &vv
}

func (c *Client) IsReachable() bool {
	_, err := c.rawRequest(http.MethodGet, "SystemInfoRpm.htm", nil, nil, "")
	return err == nil
}
