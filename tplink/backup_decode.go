package tplink

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
)

const (
	backupMagic              = 0x23892389
	offsetIP                 = 5
	offsetNetmask            = 9
	offsetGateway            = 13
	offsetDHCPFlag           = 16
	offsetHostname           = 23
	maxHostnameLen           = 32
	offsetCredentialBlob     = 0x2c
	credentialBlobLen        = 32
	offsetObfuscatedPassword = 0x49
	obfuscatedPasswordLen    = 8
	offsetMirrorDestination  = 0x00de
	offsetPortVLANMatrixBase = 0x19c
	portVLANMatrixStride     = 4
	portVLANPortCount        = 8
	offsetPortVLANMatrixLast = offsetPortVLANMatrixBase + ((portVLANPortCount - 1) * portVLANMatrixStride)
	offsetPortVLANPortIDs    = 0x418
	offsetPortVLANPortIDsEnd = offsetPortVLANPortIDs + portVLANPortCount - 1
	offsetPortVLANModeA      = 0x3f4
	offsetPortVLANModeB      = 0x3f5
	offsetVLANName           = 0x4a6
	maxVLANNameLen           = 32
	offsetStormControlBase   = 0x5d
	stormControlPortStride   = 0x10
	stormControlSlotStride   = 0x04
	stormControlPortCount    = 8
	stormControlSlotCount    = 4
	stormControlEnabledValue = 0x40
	offsetStormControlLast   = offsetStormControlBase + ((stormControlPortCount - 1) * stormControlPortStride) + ((stormControlSlotCount - 1) * stormControlSlotStride)
	offsetQoSPort1Priority   = 0x7e4
	offsetQoSPort2Priority   = 0x7eb
	offsetQoSPort3Priority   = 0x7f2
	offsetQoSPort4Priority   = 0x7f9
	offsetQoSPort5Priority   = 0x800
	offsetQoSPort6Priority   = 0x807
	offsetQoSPort7Priority   = 0x80e
	offsetQoSPort8Priority   = 0x815
	qosPortPriorityStride    = 7
	qosPortCount             = 8
	offsetLoopPreventionFlag = 0x831
	offsetLoopPreventionMode = 0x83b
	offsetIGMPFlag           = 0x83e
	offsetIGMPReportSuppFlag = 0x83f
	offsetQoSModeSigA        = 0x847
	offsetQoSModeSigB        = 0x84b
	offsetQoSModeSigC        = 0x853
	offsetLEDFlag            = 0x8c8
	minUsernameLen           = 1
	maxUsernameLen           = 16
	minPasswordLen           = 6
	maxPasswordLen           = 16
)

var knownPasswordXORKey = [obfuscatedPasswordLen]byte{0x5c, 0x74, 0x6a, 0x04, 0x7d, 0xbe, 0xb0, 0xb2}

type BackupCredentialReport struct {
	BlobHex               string
	PrintableFragments    []string
	CandidateMatches      []string
	LikelyMeaning         string
	ObfuscatedPasswordHex string
	RecoveredPassword     string
	RecoveryMethod        string
}

type BackupDiffRun struct {
	Offset int
	Length int
}

type BackupDiffReport struct {
	BaseSize                    int
	CandidateSize               int
	ComparedBytes               int
	ChangedByteCount            int
	ChangedRuns                 []BackupDiffRun
	FieldChanges                []string
	CredentialBlockChanged      bool
	CredentialBlockChangedBytes int
	PasswordSlotChanged         bool
	PasswordSlotChangedBytes    int
	BaseCredentialHex           string
	CandidateCredentialHex      string
}

type DecodedBackupConfig struct {
	Size                         int
	Magic                        uint32
	IP                           string
	Netmask                      string
	Gateway                      string
	DHCPEnabled                  bool
	MirrorDestinationPresent     bool
	MirrorDestinationKnown       bool
	MirrorDestinationPort        int
	QoSModePresent               bool
	QoSModeKnown                 bool
	QoSMode                      string
	QoSModeSignature             [3]byte
	QoSPortPrioritiesPresent     bool
	QoSPortPrioritiesKnown       bool
	QoSPortPriorities            [qosPortCount]int
	QoSPort1PriorityPresent      bool
	QoSPort1PriorityKnown        bool
	QoSPort1Priority             int
	PortVLANModePresent          bool
	PortVLANModeKnown            bool
	PortVLANModeEnabled          bool
	PortVLANModeSignature        [2]byte
	PortVLANMatrixPresent        bool
	PortVLANMatrix               [portVLANPortCount]byte
	PortVLANPortIDsPresent       bool
	PortVLANPortIDs              [portVLANPortCount]byte
	StormControlPresent          bool
	StormControlRaw              [stormControlPortCount][stormControlSlotCount]byte
	LoopPreventionPresent        bool
	LoopPreventionEnabled        bool
	IGMPSnoopingPresent          bool
	IGMPSnoopingEnabled          bool
	IGMPReportSuppressionPresent bool
	IGMPReportSuppressionEnabled bool
	LEDPresent                   bool
	LEDEnabled                   bool
	Hostname                     string
	VLANName                     string
	CredentialBlob               []byte
	CredentialInfo               BackupCredentialReport
}

func DecodeBackupConfig(data []byte) (DecodedBackupConfig, error) {
	minLen := offsetVLANName + maxVLANNameLen
	if len(data) < minLen {
		return DecodedBackupConfig{}, fmt.Errorf("backup too short: got %d bytes, want >= %d", len(data), minLen)
	}

	magic := binary.BigEndian.Uint32(data[:4])
	if magic != backupMagic {
		return DecodedBackupConfig{}, fmt.Errorf("unexpected backup magic: got %#x", magic)
	}

	cred := bytes.Clone(data[offsetCredentialBlob : offsetCredentialBlob+credentialBlobLen])
	mirrorDestinationPresent := len(data) > offsetMirrorDestination
	mirrorDestinationKnown := false
	mirrorDestinationPort := 0
	qosPresent := len(data) > offsetQoSModeSigC
	qosSignature := [3]byte{}
	qosMode := ""
	qosKnown := false
	qosPort1PriorityPresent := len(data) > offsetQoSPort1Priority
	qosPort1Priority := 0
	qosPort1PriorityKnown := false
	portVLANModePresent := len(data) > offsetPortVLANModeB
	portVLANModeKnown := false
	portVLANModeEnabled := false
	portVLANModeSignature := [2]byte{}
	portVLANMatrixPresent := len(data) > offsetPortVLANMatrixLast
	portVLANMatrix := [portVLANPortCount]byte{}
	portVLANPortIDsPresent := len(data) > offsetPortVLANPortIDsEnd
	portVLANPortIDs := [portVLANPortCount]byte{}
	qosPortPrioritiesPresent := len(data) > offsetQoSPort8Priority
	qosPortPrioritiesKnown := false
	qosPortPriorities := [qosPortCount]int{}
	stormControlPresent := len(data) > offsetStormControlLast
	stormControlRaw := [stormControlPortCount][stormControlSlotCount]byte{}
	if qosPresent {
		qosSignature = [3]byte{data[offsetQoSModeSigA], data[offsetQoSModeSigB], data[offsetQoSModeSigC]}
		qosMode, qosKnown = decodeQoSModeSignature(qosSignature)
	}
	if mirrorDestinationPresent {
		mirrorDestinationPort, mirrorDestinationKnown = decodeMirrorDestinationValue(data[offsetMirrorDestination])
	}
	if portVLANModePresent {
		portVLANModeSignature = [2]byte{data[offsetPortVLANModeA], data[offsetPortVLANModeB]}
		portVLANModeEnabled, portVLANModeKnown = decodePortVLANModeSignature(portVLANModeSignature)
	}
	if portVLANMatrixPresent {
		for i := 0; i < portVLANPortCount; i++ {
			portVLANMatrix[i] = data[offsetPortVLANMatrixBase+(i*portVLANMatrixStride)]
		}
	}
	if portVLANPortIDsPresent {
		for i := 0; i < portVLANPortCount; i++ {
			portVLANPortIDs[i] = data[offsetPortVLANPortIDs+i]
		}
	}
	if stormControlPresent {
		for port := 0; port < stormControlPortCount; port++ {
			for slot := 0; slot < stormControlSlotCount; slot++ {
				offset := stormControlOffset(port, slot)
				stormControlRaw[port][slot] = data[offset]
			}
		}
	}
	if qosPortPrioritiesPresent {
		qosPortPrioritiesKnown = true
		for i := 0; i < qosPortCount; i++ {
			offset := offsetQoSPort1Priority + (i * qosPortPriorityStride)
			priority, known := decodeQoSPortPriorityValue(data[offset])
			qosPortPriorities[i] = priority
			if !known {
				qosPortPrioritiesKnown = false
			}
		}
	}
	if qosPort1PriorityPresent {
		qosPort1Priority, qosPort1PriorityKnown = decodeQoSPortPriorityValue(data[offsetQoSPort1Priority])
	}
	loopPresent := len(data) > offsetLoopPreventionFlag
	igmpPresent := len(data) > offsetIGMPFlag
	igmpReportSuppPresent := len(data) > offsetIGMPReportSuppFlag
	ledPresent := len(data) > offsetLEDFlag
	decoded := DecodedBackupConfig{
		Size:                         len(data),
		Magic:                        magic,
		IP:                           ip4String(data[offsetIP : offsetIP+4]),
		Netmask:                      ip4String(data[offsetNetmask : offsetNetmask+4]),
		Gateway:                      ip4String(data[offsetGateway : offsetGateway+4]),
		DHCPEnabled:                  data[offsetDHCPFlag] != 0,
		MirrorDestinationPresent:     mirrorDestinationPresent,
		MirrorDestinationKnown:       mirrorDestinationKnown,
		MirrorDestinationPort:        mirrorDestinationPort,
		QoSModePresent:               qosPresent,
		QoSModeKnown:                 qosKnown,
		QoSMode:                      qosMode,
		QoSModeSignature:             qosSignature,
		QoSPortPrioritiesPresent:     qosPortPrioritiesPresent,
		QoSPortPrioritiesKnown:       qosPortPrioritiesKnown,
		QoSPortPriorities:            qosPortPriorities,
		QoSPort1PriorityPresent:      qosPort1PriorityPresent,
		QoSPort1PriorityKnown:        qosPort1PriorityKnown,
		QoSPort1Priority:             qosPort1Priority,
		PortVLANModePresent:          portVLANModePresent,
		PortVLANModeKnown:            portVLANModeKnown,
		PortVLANModeEnabled:          portVLANModeEnabled,
		PortVLANModeSignature:        portVLANModeSignature,
		PortVLANMatrixPresent:        portVLANMatrixPresent,
		PortVLANMatrix:               portVLANMatrix,
		PortVLANPortIDsPresent:       portVLANPortIDsPresent,
		PortVLANPortIDs:              portVLANPortIDs,
		StormControlPresent:          stormControlPresent,
		StormControlRaw:              stormControlRaw,
		LoopPreventionPresent:        loopPresent,
		LoopPreventionEnabled:        loopPresent && data[offsetLoopPreventionFlag] != 0,
		IGMPSnoopingPresent:          igmpPresent,
		IGMPSnoopingEnabled:          igmpPresent && data[offsetIGMPFlag] != 0,
		IGMPReportSuppressionPresent: igmpReportSuppPresent,
		IGMPReportSuppressionEnabled: igmpReportSuppPresent && data[offsetIGMPReportSuppFlag] != 0,
		LEDPresent:                   ledPresent,
		LEDEnabled:                   ledPresent && data[offsetLEDFlag] != 0,
		Hostname:                     readCString(data, offsetHostname, maxHostnameLen),
		VLANName:                     readCString(data, offsetVLANName, maxVLANNameLen),
		CredentialBlob:               cred,
		CredentialInfo:               AnalyzeCredentialBlob(cred),
	}
	decoded.CredentialInfo.ObfuscatedPasswordHex, decoded.CredentialInfo.RecoveredPassword, decoded.CredentialInfo.RecoveryMethod = recoverObfuscatedPassword(data)
	return decoded, nil
}

func CompareBackupConfigs(base []byte, candidate []byte) (BackupDiffReport, error) {
	baseDecoded, err := DecodeBackupConfig(base)
	if err != nil {
		return BackupDiffReport{}, fmt.Errorf("decode base backup: %w", err)
	}
	candidateDecoded, err := DecodeBackupConfig(candidate)
	if err != nil {
		return BackupDiffReport{}, fmt.Errorf("decode candidate backup: %w", err)
	}

	compared := len(base)
	if len(candidate) < compared {
		compared = len(candidate)
	}

	report := BackupDiffReport{
		BaseSize:                    len(base),
		CandidateSize:               len(candidate),
		ComparedBytes:               compared,
		BaseCredentialHex:           hex.EncodeToString(baseDecoded.CredentialBlob),
		CandidateCredentialHex:      hex.EncodeToString(candidateDecoded.CredentialBlob),
		CredentialBlockChangedBytes: credentialDiffBytes(baseDecoded.CredentialBlob, candidateDecoded.CredentialBlob),
		PasswordSlotChangedBytes:    regionDiffBytes(base, candidate, offsetObfuscatedPassword, obfuscatedPasswordLen),
	}
	report.CredentialBlockChanged = report.CredentialBlockChangedBytes > 0
	report.PasswordSlotChanged = report.PasswordSlotChangedBytes > 0

	runStart := -1
	runLen := 0
	for i := 0; i < compared; i++ {
		if base[i] == candidate[i] {
			if runStart >= 0 {
				report.ChangedRuns = append(report.ChangedRuns, BackupDiffRun{Offset: runStart, Length: runLen})
				runStart = -1
				runLen = 0
			}
			continue
		}

		report.ChangedByteCount++
		if runStart < 0 {
			runStart = i
			runLen = 1
			continue
		}
		runLen++
	}
	if runStart >= 0 {
		report.ChangedRuns = append(report.ChangedRuns, BackupDiffRun{Offset: runStart, Length: runLen})
	}

	if len(base) != len(candidate) {
		extra := absInt(len(base) - len(candidate))
		report.ChangedByteCount += extra
		report.ChangedRuns = append(report.ChangedRuns, BackupDiffRun{Offset: compared, Length: extra})
	}

	appendFieldChange(&report.FieldChanges, "Hostname", baseDecoded.Hostname, candidateDecoded.Hostname)
	appendFieldChange(&report.FieldChanges, "IP", baseDecoded.IP, candidateDecoded.IP)
	appendFieldChange(&report.FieldChanges, "Netmask", baseDecoded.Netmask, candidateDecoded.Netmask)
	appendFieldChange(&report.FieldChanges, "Gateway", baseDecoded.Gateway, candidateDecoded.Gateway)
	appendFieldChange(&report.FieldChanges, "DHCP", ternary(baseDecoded.DHCPEnabled, "enabled", "disabled"), ternary(candidateDecoded.DHCPEnabled, "enabled", "disabled"))
	appendFieldChange(&report.FieldChanges, "Mirror destination", mirrorDestinationState(baseDecoded), mirrorDestinationState(candidateDecoded))
	appendFieldChange(&report.FieldChanges, "Port VLAN mode", portVLANModeState(baseDecoded), portVLANModeState(candidateDecoded))
	appendFieldChange(&report.FieldChanges, "Port VLAN members", portVLANMembersState(baseDecoded), portVLANMembersState(candidateDecoded))
	appendFieldChange(&report.FieldChanges, "Port VLAN IDs", portVLANIDsState(baseDecoded), portVLANIDsState(candidateDecoded))
	appendFieldChange(&report.FieldChanges, "QoS mode", qosModeState(baseDecoded), qosModeState(candidateDecoded))
	appendFieldChange(&report.FieldChanges, "QoS priorities", qosPrioritiesState(baseDecoded), qosPrioritiesState(candidateDecoded))
	appendFieldChange(&report.FieldChanges, "QoS gi1 priority", qosPortPriorityState(baseDecoded.QoSPort1PriorityPresent, baseDecoded.QoSPort1PriorityKnown, baseDecoded.QoSPort1Priority), qosPortPriorityState(candidateDecoded.QoSPort1PriorityPresent, candidateDecoded.QoSPort1PriorityKnown, candidateDecoded.QoSPort1Priority))
	for port := 0; port < stormControlPortCount; port++ {
		for slot := 0; slot < stormControlSlotCount; slot++ {
			appendFieldChange(
				&report.FieldChanges,
				stormControlFieldLabel(port, slot),
				stormControlSlotState(baseDecoded.StormControlPresent, baseDecoded.StormControlRaw[port][slot]),
				stormControlSlotState(candidateDecoded.StormControlPresent, candidateDecoded.StormControlRaw[port][slot]),
			)
		}
	}
	appendFieldChange(&report.FieldChanges, "Spanning tree", optionalState(baseDecoded.LoopPreventionPresent, baseDecoded.LoopPreventionEnabled, "enabled", "disabled"), optionalState(candidateDecoded.LoopPreventionPresent, candidateDecoded.LoopPreventionEnabled, "enabled", "disabled"))
	appendFieldChange(&report.FieldChanges, "IGMP", optionalState(baseDecoded.IGMPSnoopingPresent, baseDecoded.IGMPSnoopingEnabled, "enabled", "disabled"), optionalState(candidateDecoded.IGMPSnoopingPresent, candidateDecoded.IGMPSnoopingEnabled, "enabled", "disabled"))
	appendFieldChange(&report.FieldChanges, "IGMP report-suppression", optionalState(baseDecoded.IGMPReportSuppressionPresent, baseDecoded.IGMPReportSuppressionEnabled, "enabled", "disabled"), optionalState(candidateDecoded.IGMPReportSuppressionPresent, candidateDecoded.IGMPReportSuppressionEnabled, "enabled", "disabled"))
	appendFieldChange(&report.FieldChanges, "LED", optionalState(baseDecoded.LEDPresent, baseDecoded.LEDEnabled, "on", "off"), optionalState(candidateDecoded.LEDPresent, candidateDecoded.LEDEnabled, "on", "off"))
	appendFieldChange(&report.FieldChanges, "VLAN name", baseDecoded.VLANName, candidateDecoded.VLANName)
	if baseDecoded.CredentialInfo.RecoveredPassword != "" && candidateDecoded.CredentialInfo.RecoveredPassword != "" {
		appendFieldChange(&report.FieldChanges, "Password (obfuscated@0x49)", baseDecoded.CredentialInfo.RecoveredPassword, candidateDecoded.CredentialInfo.RecoveredPassword)
	} else if report.PasswordSlotChanged {
		appendFieldChange(&report.FieldChanges, "Password slot bytes (obfuscated@0x49)", baseDecoded.CredentialInfo.ObfuscatedPasswordHex, candidateDecoded.CredentialInfo.ObfuscatedPasswordHex)
	}

	return report, nil
}

func FormatBackupDiff(report BackupDiffReport) string {
	var b strings.Builder
	changedPct := 0.0
	denominator := report.BaseSize
	if report.CandidateSize > denominator {
		denominator = report.CandidateSize
	}
	if denominator > 0 {
		changedPct = float64(report.ChangedByteCount) * 100.0 / float64(denominator)
	}

	fmt.Fprintf(&b, "Backup Diff (best-effort)\n")
	fmt.Fprintf(&b, "  Base size  : %d bytes\n", report.BaseSize)
	fmt.Fprintf(&b, "  Candidate  : %d bytes\n", report.CandidateSize)
	fmt.Fprintf(&b, "  Compared   : %d bytes\n", report.ComparedBytes)
	fmt.Fprintf(&b, "  Changed    : %d bytes (%.2f%%)\n", report.ChangedByteCount, changedPct)
	fmt.Fprintf(&b, "  Runs       : %d\n", len(report.ChangedRuns))

	if len(report.ChangedRuns) > 0 {
		fmt.Fprintf(&b, "\nChanged ranges\n")
		for _, run := range report.ChangedRuns {
			end := run.Offset + run.Length - 1
			fmt.Fprintf(&b, "  - 0x%04x..0x%04x (%d bytes)\n", run.Offset, end, run.Length)
		}
	}

	fmt.Fprintf(&b, "\nField changes\n")
	if len(report.FieldChanges) == 0 {
		fmt.Fprintf(&b, "  (none in known decoded fields)\n")
	} else {
		for _, change := range report.FieldChanges {
			fmt.Fprintf(&b, "  - %s\n", change)
		}
	}

	fmt.Fprintf(&b, "\nCredential block\n")
	fmt.Fprintf(&b, "  Changed    : %s\n", ternary(report.CredentialBlockChanged, "yes", "no"))
	fmt.Fprintf(&b, "  Delta      : %d bytes\n", report.CredentialBlockChangedBytes)
	fmt.Fprintf(&b, "  Pw slot    : %s (%d bytes changed @0x%02x)\n", ternary(report.PasswordSlotChanged, "changed", "unchanged"), report.PasswordSlotChangedBytes, offsetObfuscatedPassword)
	fmt.Fprintf(&b, "  Base       : %s\n", fallback(report.BaseCredentialHex, "(empty)"))
	fmt.Fprintf(&b, "  Candidate  : %s\n", fallback(report.CandidateCredentialHex, "(empty)"))

	return b.String()
}

func AnalyzeCredentialBlob(blob []byte) BackupCredentialReport {
	report := BackupCredentialReport{BlobHex: hex.EncodeToString(blob)}
	report.PrintableFragments = printableFragments(blob)

	if len(blob) >= 32 {
		first16 := blob[:16]
		second16 := blob[16:32]
		for _, candidate := range candidateSecrets() {
			md5Sum := md5.Sum([]byte(candidate))
			sha1Sum := sha1.Sum([]byte(candidate))
			sha256Sum := sha256.Sum256([]byte(candidate))
			appendDigestMatches(&report.CandidateMatches, candidate, "md5", md5Sum[:], blob, first16, second16)
			appendDigestMatches(&report.CandidateMatches, candidate, "sha1[:16]", sha1Sum[:16], blob, first16, second16)
			appendDigestMatches(&report.CandidateMatches, candidate, "sha256[:16]", sha256Sum[:16], blob, first16, second16)
		}
	}
	report.CandidateMatches = uniqueStringsInOrder(report.CandidateMatches)

	if len(report.CandidateMatches) == 0 {
		report.LikelyMeaning = "No direct match to common digest forms of default credentials; likely opaque/obfuscated credential material plus metadata."
	} else {
		report.LikelyMeaning = "Matches at least one common digest form; credential block may include hashed credential bytes."
	}

	return report
}

func FormatDecodedBackup(decoded DecodedBackupConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Backup Decode (best-effort)\n")
	fmt.Fprintf(&b, "  Size       : %d bytes\n", decoded.Size)
	fmt.Fprintf(&b, "  Magic      : %#08x\n", decoded.Magic)
	fmt.Fprintf(&b, "  Hostname   : %s\n", fallback(decoded.Hostname, "(empty)"))
	fmt.Fprintf(&b, "  IP         : %s\n", decoded.IP)
	fmt.Fprintf(&b, "  Netmask    : %s\n", decoded.Netmask)
	fmt.Fprintf(&b, "  Gateway    : %s\n", decoded.Gateway)
	fmt.Fprintf(&b, "  DHCP       : %s\n", ternary(decoded.DHCPEnabled, "enabled", "disabled"))
	fmt.Fprintf(&b, "  Mirror dst : %s\n", mirrorDestinationState(decoded))
	fmt.Fprintf(&b, "  Port VLAN  : %s\n", portVLANModeState(decoded))
	fmt.Fprintf(&b, "  Port VLAN M: %s\n", portVLANMembersState(decoded))
	fmt.Fprintf(&b, "  Port VLAN I: %s\n", portVLANIDsState(decoded))
	fmt.Fprintf(&b, "  QoS mode   : %s\n", qosModeState(decoded))
	fmt.Fprintf(&b, "  QoS pri map: %s\n", qosPrioritiesState(decoded))
	fmt.Fprintf(&b, "  QoS gi1 pri: %s\n", qosPortPriorityState(decoded.QoSPort1PriorityPresent, decoded.QoSPort1PriorityKnown, decoded.QoSPort1Priority))
	fmt.Fprintf(&b, "  Storm ctl  : %s\n", stormControlSummary(decoded))
	fmt.Fprintf(&b, "  STP        : %s\n", optionalState(decoded.LoopPreventionPresent, decoded.LoopPreventionEnabled, "enabled", "disabled"))
	fmt.Fprintf(&b, "  IGMP       : %s\n", optionalState(decoded.IGMPSnoopingPresent, decoded.IGMPSnoopingEnabled, "enabled", "disabled"))
	fmt.Fprintf(&b, "  IGMP RS    : %s\n", optionalState(decoded.IGMPReportSuppressionPresent, decoded.IGMPReportSuppressionEnabled, "enabled", "disabled"))
	fmt.Fprintf(&b, "  LED        : %s\n", optionalState(decoded.LEDPresent, decoded.LEDEnabled, "on", "off"))
	fmt.Fprintf(&b, "  VLAN name  : %s\n", fallback(decoded.VLANName, "(empty)"))
	fmt.Fprintf(&b, "\nCredential Block (offset 0x2c, 32 bytes)\n")
	fmt.Fprintf(&b, "  Policy     : username %d-%d [A-Za-z0-9_], password %d-%d [A-Za-z0-9_]\n", minUsernameLen, maxUsernameLen, minPasswordLen, maxPasswordLen)
	fmt.Fprintf(&b, "  Coverage   : password decode currently mapped to %d-byte obfuscated slot at 0x%02x\n", obfuscatedPasswordLen, offsetObfuscatedPassword)
	fmt.Fprintf(&b, "  Hex        : %s\n", decoded.CredentialInfo.BlobHex)
	if decoded.CredentialInfo.RecoveredPassword != "" {
		fmt.Fprintf(&b, "  Password   : %s\n", decoded.CredentialInfo.RecoveredPassword)
		fmt.Fprintf(&b, "  Pw bytes   : %s (offset 0x%02x)\n", decoded.CredentialInfo.ObfuscatedPasswordHex, offsetObfuscatedPassword)
		fmt.Fprintf(&b, "  Method     : %s\n", decoded.CredentialInfo.RecoveryMethod)
	} else if decoded.CredentialInfo.ObfuscatedPasswordHex != "" {
		fmt.Fprintf(&b, "  Password   : (not recoverable from current mapping)\n")
		fmt.Fprintf(&b, "  Pw bytes   : %s (offset 0x%02x)\n", decoded.CredentialInfo.ObfuscatedPasswordHex, offsetObfuscatedPassword)
	}
	if len(decoded.CredentialInfo.PrintableFragments) > 0 {
		fmt.Fprintf(&b, "  Strings    : %s\n", strings.Join(decoded.CredentialInfo.PrintableFragments, ", "))
	} else {
		fmt.Fprintf(&b, "  Strings    : (none)\n")
	}
	if len(decoded.CredentialInfo.CandidateMatches) > 0 {
		fmt.Fprintf(&b, "  Matches    :\n")
		for _, match := range decoded.CredentialInfo.CandidateMatches {
			fmt.Fprintf(&b, "    - %s\n", match)
		}
	} else {
		fmt.Fprintf(&b, "  Matches    : none against default credential candidates\n")
	}
	fmt.Fprintf(&b, "  Analysis   : %s\n", decoded.CredentialInfo.LikelyMeaning)
	return b.String()
}

func appendDigestMatches(matches *[]string, candidate string, digestName string, digest []byte, full []byte, first16 []byte, second16 []byte) {
	if len(digest) == 0 {
		return
	}
	if bytes.Equal(full, digest) {
		*matches = append(*matches, fmt.Sprintf("candidate=%q digest=%s section=full", candidate, digestName))
	}
	if len(digest) >= 16 {
		if bytes.Equal(first16, digest[:16]) {
			*matches = append(*matches, fmt.Sprintf("candidate=%q digest=%s section=first16", candidate, digestName))
		}
		if bytes.Equal(second16, digest[:16]) {
			*matches = append(*matches, fmt.Sprintf("candidate=%q digest=%s section=second16", candidate, digestName))
		}
	}
}

func appendFieldChange(changes *[]string, field string, before string, after string) {
	if before == after {
		return
	}
	*changes = append(*changes, fmt.Sprintf("%s: %q -> %q", field, before, after))
}

func decodeQoSModeSignature(signature [3]byte) (string, bool) {
	switch signature {
	case [3]byte{0x04, 0x05, 0x06}:
		return "dscp", true
	case [3]byte{0x05, 0x06, 0x00}:
		return "dot1p", true
	case [3]byte{0x06, 0x00, 0x00}:
		return "port-based", true
	default:
		return "", false
	}
}

func decodeQoSPortPriorityValue(raw byte) (int, bool) {
	switch raw {
	case 0x00:
		return 1, true
	case 0x02:
		return 2, true
	case 0x04:
		return 3, true
	case 0x06:
		return 4, true
	default:
		return 0, false
	}
}

func decodeMirrorDestinationValue(raw byte) (int, bool) {
	if raw == 0x00 {
		return 0, true
	}
	if raw >= 1 && raw <= portVLANPortCount {
		return int(raw), true
	}
	return 0, false
}

func mirrorDestinationState(decoded DecodedBackupConfig) string {
	if !decoded.MirrorDestinationPresent {
		return "unknown"
	}
	if !decoded.MirrorDestinationKnown {
		return fmt.Sprintf("unknown(raw@0x%02x)", offsetMirrorDestination)
	}
	if decoded.MirrorDestinationPort == 0 {
		return "disabled"
	}
	return fmt.Sprintf("gi%d", decoded.MirrorDestinationPort)
}

func decodePortVLANModeSignature(signature [2]byte) (bool, bool) {
	switch signature {
	case [2]byte{0x00, 0x01}:
		return true, true
	case [2]byte{0x01, 0x02}:
		return false, true
	default:
		return false, false
	}
}

func portVLANModeState(decoded DecodedBackupConfig) string {
	if !decoded.PortVLANModePresent {
		return "unknown"
	}
	if decoded.PortVLANModeKnown {
		if decoded.PortVLANModeEnabled {
			return "enabled"
		}
		return "disabled"
	}
	sig := decoded.PortVLANModeSignature
	return fmt.Sprintf("unknown(sig=%02x/%02x)", sig[0], sig[1])
}

func portVLANMembersState(decoded DecodedBackupConfig) string {
	if !decoded.PortVLANMatrixPresent {
		return "unknown"
	}
	return portsMaskString(decoded.PortVLANMatrix[0])
}

func portVLANIDsState(decoded DecodedBackupConfig) string {
	if !decoded.PortVLANPortIDsPresent {
		return "unknown"
	}
	parts := make([]string, 0, portVLANPortCount)
	for i := 0; i < portVLANPortCount; i++ {
		parts = append(parts, fmt.Sprintf("gi%d=%d", i+1, decoded.PortVLANPortIDs[i]))
	}
	return strings.Join(parts, ",")
}

func portsMaskString(mask byte) string {
	ports := make([]string, 0, portVLANPortCount)
	for i := 0; i < portVLANPortCount; i++ {
		if (mask & (1 << i)) == 0 {
			continue
		}
		ports = append(ports, fmt.Sprintf("gi%d", i+1))
	}
	if len(ports) == 0 {
		return "(none)"
	}
	return strings.Join(ports, ",")
}

func qosModeState(decoded DecodedBackupConfig) string {
	if !decoded.QoSModePresent {
		return "unknown"
	}
	if decoded.QoSModeKnown {
		return decoded.QoSMode
	}
	sig := decoded.QoSModeSignature
	return fmt.Sprintf("unknown(sig=%02x/%02x/%02x)", sig[0], sig[1], sig[2])
}

func qosPortPriorityState(present bool, known bool, priority int) string {
	if !present {
		return "unknown"
	}
	if !known {
		return "unknown"
	}
	return fmt.Sprintf("%d", priority)
}

func qosPrioritiesState(decoded DecodedBackupConfig) string {
	if !decoded.QoSPortPrioritiesPresent {
		return "unknown"
	}
	if !decoded.QoSPortPrioritiesKnown {
		return "unknown"
	}
	parts := make([]string, 0, qosPortCount)
	for i := 0; i < qosPortCount; i++ {
		parts = append(parts, fmt.Sprintf("gi%d=%d", i+1, decoded.QoSPortPriorities[i]))
	}
	return strings.Join(parts, ",")
}

func stormControlFieldLabel(port int, slot int) string {
	return fmt.Sprintf("Storm gi%d %s", port+1, stormControlSlotLabel(slot))
}

func stormControlSlotLabel(slot int) string {
	switch slot {
	case 0:
		return "broadcast"
	case 1:
		return "multicast"
	case 2:
		return "unknown-unicast"
	default:
		return "all"
	}
}

func stormControlOffset(port int, slot int) int {
	return offsetStormControlBase + (port * stormControlPortStride) + (slot * stormControlSlotStride)
}

func stormControlSlotState(present bool, raw byte) string {
	if !present {
		return "unknown"
	}
	switch raw {
	case 0x00:
		return "off"
	case stormControlEnabledValue:
		return "on"
	default:
		return fmt.Sprintf("unknown(0x%02x)", raw)
	}
}

func stormControlSummary(decoded DecodedBackupConfig) string {
	if !decoded.StormControlPresent {
		return "unknown"
	}
	enabled := make([]string, 0)
	unknown := make([]string, 0)
	for port := 0; port < stormControlPortCount; port++ {
		for slot := 0; slot < stormControlSlotCount; slot++ {
			raw := decoded.StormControlRaw[port][slot]
			if raw == stormControlEnabledValue {
				enabled = append(enabled, fmt.Sprintf("gi%d:%s", port+1, stormControlSlotLabel(slot)))
				continue
			}
			if raw != 0x00 {
				unknown = append(unknown, fmt.Sprintf("gi%d:%s=0x%02x", port+1, stormControlSlotLabel(slot), raw))
			}
		}
	}
	state := "all-off"
	if len(enabled) > 0 {
		state = strings.Join(enabled, ",")
	}
	if len(unknown) == 0 {
		return state
	}
	return state + ";unknown=" + strings.Join(unknown, ",")
}

func optionalState(present bool, enabled bool, whenEnabled string, whenDisabled string) string {
	if !present {
		return "unknown"
	}
	if enabled {
		return whenEnabled
	}
	return whenDisabled
}

func credentialDiffBytes(base []byte, candidate []byte) int {
	minLen := len(base)
	if len(candidate) < minLen {
		minLen = len(candidate)
	}
	diff := 0
	for i := 0; i < minLen; i++ {
		if base[i] != candidate[i] {
			diff++
		}
	}
	return diff + absInt(len(base)-len(candidate))
}

func regionDiffBytes(base []byte, candidate []byte, offset int, length int) int {
	if offset < 0 || length <= 0 {
		return 0
	}
	diff := 0
	for i := 0; i < length; i++ {
		idx := offset + i
		inBase := idx >= 0 && idx < len(base)
		inCandidate := idx >= 0 && idx < len(candidate)
		if !inBase && !inCandidate {
			continue
		}
		if inBase != inCandidate {
			diff++
			continue
		}
		if base[idx] != candidate[idx] {
			diff++
		}
	}
	return diff
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func recoverObfuscatedPassword(data []byte) (string, string, string) {
	end := offsetObfuscatedPassword + obfuscatedPasswordLen
	if len(data) < end {
		return "", "", ""
	}
	raw := data[offsetObfuscatedPassword:end]
	decoded := make([]byte, obfuscatedPasswordLen)
	for i := 0; i < obfuscatedPasswordLen; i++ {
		decoded[i] = raw[i] ^ knownPasswordXORKey[i]
	}
	trimmed := bytes.TrimRight(decoded, "\x00")
	if len(trimmed) == 0 {
		return hex.EncodeToString(raw), "", ""
	}
	if !allPrintableASCII(trimmed) || !matchesCredentialCharset(trimmed) {
		return hex.EncodeToString(raw), "", ""
	}
	if len(trimmed) < minPasswordLen {
		return hex.EncodeToString(raw), "", ""
	}
	recovered := string(trimmed)
	method := fmt.Sprintf("xor(key=5c746a047dbeb0b2, tl-sg108e-v1 inferred); recovered up to %d bytes from mapped slot", obfuscatedPasswordLen)
	if len(trimmed) > maxPasswordLen {
		method += "; decoded value exceeds known UI password max"
	}
	return hex.EncodeToString(raw), recovered, method
}

func allPrintableASCII(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	for _, ch := range data {
		if ch < 0x20 || ch > 0x7e {
			return false
		}
	}
	return true
}

func matchesCredentialCharset(data []byte) bool {
	for _, ch := range data {
		isLower := ch >= 'a' && ch <= 'z'
		isUpper := ch >= 'A' && ch <= 'Z'
		isDigit := ch >= '0' && ch <= '9'
		if !isLower && !isUpper && !isDigit && ch != '_' {
			return false
		}
	}
	return true
}

func candidateSecrets() []string {
	candidates := []string{
		"admin",
		FirmwarePassword,
		"admin:admin",
		"admin:" + FirmwarePassword,
		FirmwarePassword + ":admin",
		"TPLINK-DIST-SWITCH",
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		out = append(out, candidate)
	}
	sort.Strings(out)
	return out
}

func ip4String(raw []byte) string {
	if len(raw) != 4 {
		return "0.0.0.0"
	}
	return net.IPv4(raw[0], raw[1], raw[2], raw[3]).String()
}

func readCString(data []byte, offset int, maxLen int) string {
	if offset < 0 || offset >= len(data) || maxLen <= 0 {
		return ""
	}
	end := offset + maxLen
	if end > len(data) {
		end = len(data)
	}
	raw := data[offset:end]
	nul := bytes.IndexByte(raw, 0)
	if nul >= 0 {
		raw = raw[:nul]
	}
	return strings.TrimSpace(string(raw))
}

func printableFragments(data []byte) []string {
	fragments := []string{}
	start := -1
	for i, ch := range data {
		isPrintable := ch >= 0x20 && ch <= 0x7e
		if isPrintable {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= 2 {
			fragments = append(fragments, string(data[start:i]))
		}
		start = -1
	}
	if start >= 0 && len(data)-start >= 2 {
		fragments = append(fragments, string(data[start:]))
	}
	return fragments
}

func uniqueStringsInOrder(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func fallback(value string, empty string) string {
	if value == "" {
		return empty
	}
	return value
}
