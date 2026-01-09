package utils

import (
	"client/flowmetrics"
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Flowid struct {
	SrcIP    string
	DstIP    string
	SrcPort  string
	DstPort  string
	Protocol int
}

func (f Flowid) String() string {
	return fmt.Sprintf("%s-%s-%s-%s-%d", f.SrcIP, f.DstIP, f.SrcPort, f.DstPort, f.Protocol)
}

type Flow struct {
	Flowid                 Flowid
	SrcIP                  string
	DstIP                  string
	SrcPort                string
	DstPort                string
	Protocol               int
	TotalfwdPackets        int
	TotalbwdPackets        int
	FPSH_cnt               int
	BPSH_cnt               int
	FURG_cnt               int
	BURG_cnt               int
	FwdFINCount            int
	BwdFINCount            int
	FwdHeaderLength        int64 // Total transport header bytes in forward direction
	BwdHeaderLength        int64 // Total transport header bytes in backward direction
	TotalLengthofFwdPacket int64 // Total size of packet in forward direction
	TotalLengthofBwdPacket int64 // Total size of packet in backward direction
	Timestamp              time.Time
	LastSeenTime           time.Time
	FwdLastSeenTime        time.Time
	BwdLastSeenTime        time.Time

	// for calculation
	FwdPktStats flowmetrics.Stats
	BwdPktStats flowmetrics.Stats
	PktLenStats flowmetrics.Stats
	FlowIAT     flowmetrics.IATStats
	FwdIAT      flowmetrics.IATStats
	BwdIAT      flowmetrics.IATStats

	FlowDuration         int64   // in microseconds
	FwdPacketLengthMin   float64 // Minimum size of packet in forward direction
	FwdPacketLengthMax   float64 // Maximum size of packet in forward direction
	FwdPacketLengthMean  float64 // Mean size of packet in forward direction
	FwdPacketLengthStd   float64 // Standard deviation size of packet in forward direction
	BwdPacketLengthMin   float64 // Minimum size of packet in backward direction
	BwdPacketLengthMax   float64 // Maximum size of packet in backward direction
	BwdPacketLengthMean  float64 // Mean size of packet in backward direction
	BwdPacketLengthStd   float64 // Standard deviation size of packet in backward direction
	FlowBytesPerSecond   float64 // Number of flow bytes per second
	FlowPacketsPerSecond float64 // Number of flow packets per second
	FwdPacketsPerSecond  float64 // Number of forward packets per second
	BwdPacketsPerSecond  float64 // Number of backward packets per second

	FlowIATMean  float64 // Mean time between two packets sent in the flow
	FlowIATStd   float64 // Standard deviation time between two packets sent in the flow
	FlowIATMax   float64 // Maximum time between two packets sent in the flow
	FlowIATMin   float64 // Minimum time between two packets sent in the flow
	PktLenMin    float64 // Minimum payload bytes among all packets
	PktLenMax    float64 // Maximum payload bytes among all packets
	PktLenMean   float64 // Mean payload bytes among all packets
	PktLenStd    float64 // Stddev payload bytes among all packets
	PktLenVar    float64 // Variance payload bytes among all packets
	FINFlagCount int     // Number of packets with FIN flag set
	SYNFlagCount int     // Number of packets with SYN flag set
	RSTFlagCount int     // Number of packets with RST flag set
	PSHFlagCount int     // Number of packets with PSH flag set
	ACKFlagCount int     // Number of packets with ACK flag set
	URGFlagCount int     // Number of packets with URG flag set
	CWRFlagCount int     // Number of packets with CWR flag set
	ECEFlagCount int     // Number of packets with ECE flag set
	FwdIATMin    float64 // Minimum time between two packets sent in the forward direction
	FwdIATMax    float64 // Maximum time between two packets sent in the forward direction
	FwdIATMean   float64 // Mean time between two packets sent in the forward direction
	FwdIATStd    float64 // Standard deviation time between two packets sent in the forward direction
	FwdIATTotal  float64 // Total time between two packets sent in the forward direction
	BwdIATMin    float64 // Minimum time between two packets sent in the backward direction
	BwdIATMax    float64 // Maximum time between two packets sent in the backward direction
	BwdIATMean   float64 // Mean time between two packets sent in the backward direction
	BwdIATStd    float64 // Standard deviation time between two packets sent in the backward direction
	BwdIATTotal  float64 // Total time between two packets sent in the backward direction
}

// PacketTimestamp returns a stable timestamp for a packet.
// If the capture timestamp is missing, it falls back to time.Now().
func PacketTimestamp(packet gopacket.Packet) time.Time {
	ts := packet.Metadata().Timestamp
	if ts.IsZero() {
		return time.Now()
	}
	return ts
}

// FlowPacketCount returns the total packet count of a flow.
func FlowPacketCount(flow *Flow) int {
	if flow == nil {
		return 0
	}
	return flow.TotalfwdPackets + flow.TotalbwdPackets
}

// HasAbsoluteFlowTimedOut implements CICFlowMeter-like absolute timeout:
// (currentTimestamp - flowStartTime) > flowTimeOut.
func HasAbsoluteFlowTimedOut(flow *Flow, currentTime time.Time, flowTimeOut time.Duration) bool {
	if flow == nil {
		return false
	}
	if flowTimeOut <= 0 {
		return false
	}
	if flow.Timestamp.IsZero() {
		return false
	}
	return currentTime.Sub(flow.Timestamp) > flowTimeOut
}

// IsForwardPacket reports whether packet direction matches the flow's original 5-tuple.
func IsForwardPacket(flow *Flow, packet gopacket.Packet) bool {
	if flow == nil {
		return true
	}

	n := packet.NetworkLayer()
	t := packet.TransportLayer()
	if n == nil || t == nil {
		return true
	}

	srcIP := n.NetworkFlow().Src().String()
	dstIP := n.NetworkFlow().Dst().String()
	srcPort := t.TransportFlow().Src().String()
	dstPort := t.TransportFlow().Dst().String()

	return srcIP == flow.SrcIP && dstIP == flow.DstIP && srcPort == flow.SrcPort && dstPort == flow.DstPort
}

// TCPFlags returns whether a packet has TCP FIN/RST flags set.
func TCPFlags(packet gopacket.Packet) (hasFIN bool, hasRST bool) {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		if tcp, ok := tcpLayer.(*layers.TCP); ok {
			return tcp.FIN, tcp.RST
		}
	}
	return false, false
}

// TCPPSHURGFlags returns whether a packet has TCP PSH/URG flags set.
// For non-TCP packets it returns (false, false).
func TCPPSHURGFlags(packet gopacket.Packet) (hasPSH bool, hasURG bool) {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		if tcp, ok := tcpLayer.(*layers.TCP); ok {
			return tcp.PSH, tcp.URG
		}
	}
	return false, false
}

// UpdateFINCounters increments CIC-like FIN counters.
func UpdateFINCounters(flow *Flow, isForward bool) {
	if flow == nil {
		return
	}
	if isForward {
		flow.FwdFINCount++
	} else {
		flow.BwdFINCount++
	}
}

// IsFINTeardownComplete implements a simple CIC-style FIN completion heuristic:
// - complete when both directions have seen FIN at least once, OR
// - complete when either direction has seen FIN twice (retransmit/teardown progress).
func IsFINTeardownComplete(flow *Flow) bool {
	if flow == nil {
		return false
	}
	if flow.FwdFINCount >= 1 && flow.BwdFINCount >= 1 {
		return true
	}
	if flow.FwdFINCount >= 2 || flow.BwdFINCount >= 2 {
		return true
	}
	return false
}
