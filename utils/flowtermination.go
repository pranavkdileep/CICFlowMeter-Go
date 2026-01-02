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
	FwdFINCount            int
	BwdFINCount            int
	TotalLengthofFwdPacket int64 // Total size of packet in forward direction
	TotalLengthofBwdPacket int64 // Total size of packet in backward direction
	Timestamp              time.Time
	LastSeenTime           time.Time
	FwdLastSeenTime        time.Time
	BwdLastSeenTime        time.Time

	// for calculation
	FwdPktStats flowmetrics.Stats
	BwdPktStats flowmetrics.Stats
	FlowIAT     flowmetrics.IATStats
	FwdIAT     flowmetrics.IATStats
	BwdIAT     flowmetrics.IATStats

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

	FlowIATMean			float64	// Mean time between two packets sent in the flow
	FlowIATStd			float64	// Standard deviation time between two packets sent in the flow
	FlowIATMax			float64	// Maximum time between two packets sent in the flow
	FlowIATMin			float64	// Minimum time between two packets sent in the flow
	FwdIATMin			float64	// Minimum time between two packets sent in the forward direction
	FwdIATMax			float64	// Maximum time between two packets sent in the forward direction
	FwdIATMean			float64	// Mean time between two packets sent in the forward direction
	FwdIATStd			float64	// Standard deviation time between two packets sent in the forward direction
	FwdIATTotal   		float64	// Total time between two packets sent in the forward direction
	BwdIATMin			float64	// Minimum time between two packets sent in the backward direction
	BwdIATMax			float64	// Maximum time between two packets sent in the backward direction
	BwdIATMean			float64	// Mean time between two packets sent in the backward direction
	BwdIATStd			float64	// Standard deviation time between two packets sent in the backward direction
	BwdIATTotal			float64	// Total time between two packets sent in the backward direction
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
