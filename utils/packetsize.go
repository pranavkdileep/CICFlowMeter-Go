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
