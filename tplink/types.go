package tplink

import "fmt"

const FirmwarePassword = "testpass"

type PortSpeed int

const (
	PortSpeedAuto   PortSpeed = 1
	PortSpeedM10H   PortSpeed = 2
	PortSpeedM10F   PortSpeed = 3
	PortSpeedM100H  PortSpeed = 4
	PortSpeedM100F  PortSpeed = 5
	PortSpeedM1000F PortSpeed = 6
)

func (s PortSpeed) String() string {
	switch s {
	case PortSpeedAuto:
		return "Auto"
	case PortSpeedM10H:
		return "10M-Half"
	case PortSpeedM10F:
		return "10M-Full"
	case PortSpeedM100H:
		return "100M-Half"
	case PortSpeedM100F:
		return "100M-Full"
	case PortSpeedM1000F:
		return "1000M-Full"
	default:
		return "Unknown"
	}
}

type QoSMode int

const (
	QoSModePortBased QoSMode = 0
	QoSModeDot1P     QoSMode = 1
	QoSModeDSCP      QoSMode = 2
)

type StormType int

const (
	StormTypeUnknownUnicast StormType = 1
	StormTypeMulticast      StormType = 2
	StormTypeBroadcast      StormType = 4
)

func AllStormTypes() []StormType {
	return []StormType{StormTypeUnknownUnicast, StormTypeMulticast, StormTypeBroadcast}
}

var StormRateKbps = map[int]int{
	1: 64, 2: 128, 3: 256, 4: 512,
	5: 1024, 6: 2048, 7: 4096, 8: 8192,
	9: 16384, 10: 32768, 11: 65536, 12: 131072,
}

var bandwidthRateKbps = map[int]struct{}{
	0: {}, 512: {}, 1024: {}, 2048: {}, 4096: {},
	8192: {}, 16384: {}, 32768: {}, 65536: {}, 131072: {},
	262144: {}, 524288: {}, 1000000: {},
}

type SystemInfo struct {
	Description string
	MAC         string
	IP          string
	Netmask     string
	Gateway     string
	Firmware    string
	Hardware    string
}

func (s SystemInfo) String() string {
	return fmt.Sprintf(
		"SystemInfo(%s, MAC=%s, IP=%s/%s, GW=%s, FW=%s, HW=%s)",
		s.Description,
		s.MAC,
		s.IP,
		s.Netmask,
		s.Gateway,
		s.Firmware,
		s.Hardware,
	)
}

type IPSettings struct {
	DHCP    bool
	IP      string
	Netmask string
	Gateway string
}

type PortInfo struct {
	Port     int
	Enabled  bool
	SpeedCfg *PortSpeed
	SpeedAct *PortSpeed
	FCCfg    bool
	FCAct    bool
	TrunkID  int
}

func (p PortInfo) String() string {
	state := "DOWN"
	if p.Enabled {
		state = "UP"
	}
	out := fmt.Sprintf("Port %2d: %s", p.Port, state)
	if p.SpeedAct != nil {
		out += " actual=" + p.SpeedAct.String()
	}
	if p.SpeedCfg != nil {
		out += " cfg=" + p.SpeedCfg.String()
	}
	if p.FCCfg {
		out += " FC=on"
	}
	if p.TrunkID != 0 {
		out += fmt.Sprintf(" LAG%d", p.TrunkID)
	}
	return out
}

type PortStats struct {
	Port   int
	TXPkts int
	RXPkts int
}

type MirrorConfig struct {
	Enabled      bool
	DestPort     int
	Mode         int
	IngressPorts []int
	EgressPorts  []int
}

type TrunkConfig struct {
	MaxGroups int
	PortCount int
	Groups    map[int][]int
}

type IGMPConfig struct {
	Enabled           bool
	ReportSuppression bool
	GroupCount        int
}

type MTUVlanConfig struct {
	Enabled    bool
	PortCount  int
	UplinkPort int
}

type PortVlanEntry struct {
	VID     int
	Members int
}

type Dot1QVlanEntry struct {
	VID             int
	Name            string
	TaggedMembers   int
	UntaggedMembers int
}

type QoSPortConfig struct {
	Port     int
	Priority int
}

type BandwidthEntry struct {
	Port        int
	IngressRate int
	EgressRate  int
}

type StormEntry struct {
	Port       int
	Enabled    bool
	RateIndex  int
	StormTypes int
}

type CableDiagResult struct {
	Port    int
	Status  string
	LengthM int
}

func BitsToPorts(mask int, portCount int) []int {
	if portCount <= 0 {
		portCount = 8
	}
	out := make([]int, 0, portCount)
	for i := 0; i < portCount; i++ {
		if mask&(1<<i) != 0 {
			out = append(out, i+1)
		}
	}
	return out
}

func PortsToBits(ports []int) int {
	mask := 0
	for _, p := range ports {
		if p > 0 {
			mask |= 1 << (p - 1)
		}
	}
	return mask
}
