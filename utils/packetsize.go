package utils

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func GetPacketSize(packet gopacket.Packet) int64 {
	if l := packet.Layer(layers.LayerTypeTCP); l != nil {
		tcp := l.(*layers.TCP)
		return int64(len(tcp.Payload))
	}
	if l := packet.Layer(layers.LayerTypeUDP); l != nil {
		udp := l.(*layers.UDP)
		return int64(len(udp.Payload))
	}
	// CICFlowMeter is mainly about TCP/UDP flows; for others they often ignore or treat as 0.
	return 0
}

// GetTransportHeaderBytes returns the L4 header length in bytes.
// This matches CICFlowMeter's notion of "Header Length" per packet (TCP data offset, UDP fixed 8 bytes).
func GetTransportHeaderBytes(packet gopacket.Packet) int64 {
	if l := packet.Layer(layers.LayerTypeTCP); l != nil {
		tcp := l.(*layers.TCP)
		// TCP data offset is in 32-bit words.
		return int64(tcp.DataOffset) * 4
	}
	if packet.Layer(layers.LayerTypeUDP) != nil {
		return 8
	}
	return 0
}
