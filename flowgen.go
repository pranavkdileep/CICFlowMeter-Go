package main

import (
	"client/flowmetrics"
	"client/utils"
	"encoding/csv"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func dispatchPacketToFlow(ch chan gopacket.Packet, flowmap map[utils.Flowid]*utils.Flow, wg *sync.WaitGroup, mu *sync.Mutex, packetcount *int, writer *csv.Writer) {
	defer wg.Done()

	flowTimeOut := 120 * time.Second

	addPacket := func(flow *utils.Flow, packet gopacket.Packet, isForward bool, ts time.Time) {
		size := utils.GetPacketSize(packet)
		headerBytes := utils.GetTransportHeaderBytes(packet)
		flow.PktLenStats.AddValue(float64(size))

		// Bidirectional TCP flag counts (CICFlowMeter-like): increment per packet.
		if flow.Protocol == 6 {
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				if tcp, ok := tcpLayer.(*layers.TCP); ok {
					if tcp.FIN {
						flow.FINFlagCount++
					}
					if tcp.SYN {
						flow.SYNFlagCount++
					}
					if tcp.RST {
						flow.RSTFlagCount++
					}
					if tcp.PSH {
						flow.PSHFlagCount++
					}
					if tcp.ACK {
						flow.ACKFlagCount++
					}
					if tcp.URG {
						flow.URGFlagCount++
					}
					if tcp.CWR {
						flow.CWRFlagCount++
					}
					if tcp.ECE {
						flow.ECEFlagCount++
					}
				}
			}
		}
		prevTotal := flow.TotalfwdPackets + flow.TotalbwdPackets
		if prevTotal >= 1 && !flow.LastSeenTime.IsZero() {
			flow.FlowIAT.AddValue(float64(ts.Sub(flow.LastSeenTime).Microseconds()))
		}

		// TCP-only directional flag counters (UDP remains 0).
		if flow.Protocol == 6 {
			hasPSH, hasURG := utils.TCPPSHURGFlags(packet)
			if isForward {
				if hasPSH {
					flow.FPSH_cnt++
				}
				if hasURG {
					flow.FURG_cnt++
				}
			} else {
				if hasPSH {
					flow.BPSH_cnt++
				}
				if hasURG {
					flow.BURG_cnt++
				}
			}
		}

		if isForward {
			prevFwd := flow.TotalfwdPackets
			if prevFwd >= 1 && !flow.FwdLastSeenTime.IsZero() {
				flow.FwdIAT.AddValue(float64(ts.Sub(flow.FwdLastSeenTime).Microseconds()))
			}
			flow.TotalfwdPackets++
			flow.FwdHeaderLength += headerBytes
			flow.FwdPktStats.AddValue(float64(size))
			flow.TotalLengthofFwdPacket += size
			flow.FwdLastSeenTime = ts
		} else {
			prevBwd := flow.TotalbwdPackets
			if prevBwd >= 1 && !flow.BwdLastSeenTime.IsZero() {
				flow.BwdIAT.AddValue(float64(ts.Sub(flow.BwdLastSeenTime).Microseconds()))
			}
			flow.TotalbwdPackets++
			flow.BwdHeaderLength += headerBytes
			flow.BwdPktStats.AddValue(float64(size))
			flow.TotalLengthofBwdPacket += size
			flow.BwdLastSeenTime = ts
		}

		flow.LastSeenTime = ts
	}

	newFlowFromTemplate := func(flowID utils.Flowid, template *utils.Flow, ts time.Time) *utils.Flow {
		return &utils.Flow{
			Flowid:                 flowID,
			SrcIP:                  template.SrcIP,
			DstIP:                  template.DstIP,
			SrcPort:                template.SrcPort,
			DstPort:                template.DstPort,
			Protocol:               template.Protocol,
			TotalfwdPackets:        0,
			TotalbwdPackets:        0,
			FwdHeaderLength:        0,
			BwdHeaderLength:        0,
			FwdPktStats:            flowmetrics.NewStats(),
			BwdPktStats:            flowmetrics.NewStats(),
			PktLenStats:            flowmetrics.NewStats(),
			FlowIAT:                flowmetrics.NewIATStats(),
			FwdIAT:                 flowmetrics.NewIATStats(),
			BwdIAT:                 flowmetrics.NewIATStats(),
			TotalLengthofFwdPacket: 0,
			TotalLengthofBwdPacket: 0,
			Timestamp:              ts,
			LastSeenTime:           ts,
			FwdLastSeenTime:        time.Time{},
			BwdLastSeenTime:        time.Time{},
		}
	}

	newFlowForFirstPacket := func(flowID utils.Flowid, ts time.Time) *utils.Flow {
		return &utils.Flow{
			Flowid:                 flowID,
			SrcIP:                  flowID.SrcIP,
			DstIP:                  flowID.DstIP,
			SrcPort:                flowID.SrcPort,
			DstPort:                flowID.DstPort,
			Protocol:               flowID.Protocol,
			TotalfwdPackets:        0,
			TotalbwdPackets:        0,
			FwdHeaderLength:        0,
			BwdHeaderLength:        0,
			FwdPktStats:            flowmetrics.NewStats(),
			BwdPktStats:            flowmetrics.NewStats(),
			PktLenStats:            flowmetrics.NewStats(),
			FlowIAT:                flowmetrics.NewIATStats(),
			FwdIAT:                 flowmetrics.NewIATStats(),
			BwdIAT:                 flowmetrics.NewIATStats(),
			TotalLengthofFwdPacket: 0,
			TotalLengthofBwdPacket: 0,
			Timestamp:              ts,
			LastSeenTime:           ts,
			FwdLastSeenTime:        ts,
		}
	}

	for packet := range ch {
		networkLayer := packet.NetworkLayer()
		if networkLayer != nil {
			if networkLayer.NetworkFlow().EndpointType().String() == "IPv4" {
				flowID := generateFlowID(packet)
				mu.Lock()
				*packetcount++
				packetTs := utils.PacketTimestamp(packet)

				// Find an existing bidirectional flow (either direct or reverse key).
				key := flowID
				isForward := true
				flow := flowmap[key]
				if flow == nil {
					reverseFlowID := generateReverseFlowID(packet)
					key = reverseFlowID
					flow = flowmap[key]
					isForward = false
				}

				if flow == nil {
					// Create new flow for first packet.
					flow = newFlowForFirstPacket(flowID, packetTs)
					flowmap[flowID] = flow
					key = flowID
					isForward = true
				}

				if utils.HasAbsoluteFlowTimedOut(flow, packetTs, flowTimeOut) {
					if utils.FlowPacketCount(flow) > 1 {
						flowComplete(key, flowmap, writer)
					} else {
						delete(flowmap, key)
					}

					template := flow
					flow = newFlowFromTemplate(key, template, packetTs)
					flowmap[key] = flow
				}

				// Add current packet to flow (forward/backward accounting).
				addPacket(flow, packet, isForward, packetTs)

				// TCP termination flags: RST immediate; FIN tracked until teardown complete.
				if flow.Protocol == 6 {
					hasFIN, hasRST := utils.TCPFlags(packet)
					if hasRST {
						flowComplete(key, flowmap, writer)
						mu.Unlock()
						wg.Done()
						continue
					}
					if hasFIN {
						utils.UpdateFINCounters(flow, isForward)
						flowComplete(key, flowmap, writer)
						mu.Unlock()
						wg.Done()
						continue
					}
				}

				mu.Unlock()
				wg.Done()
			}
		}
	}
}

func flowComplete(flowid utils.Flowid, flowmap map[utils.Flowid]*utils.Flow, writer *csv.Writer) {
	flow, exists := flowmap[flowid]
	if !exists {
		return
	}

	flow.FlowDuration = flowmetrics.CalculateFlowDuration(
		flow.Timestamp,
		flow.LastSeenTime,
	)
	flow.FwdPacketLengthMin = flowmetrics.FwdPacketLengthMin(flow.FwdPktStats)
	flow.FwdPacketLengthMax = flowmetrics.FwdPacketLengthMax(flow.FwdPktStats)
	flow.FwdPacketLengthMean = flowmetrics.FwdPacketLengthMean(flow.FwdPktStats)
	flow.FwdPacketLengthStd = flowmetrics.FwdPacketLengthStd(flow.FwdPktStats)
	flow.BwdPacketLengthMin = flowmetrics.BwdPacketLengthMin(flow.BwdPktStats)
	flow.BwdPacketLengthMax = flowmetrics.BwdPacketLengthMax(flow.BwdPktStats)
	flow.BwdPacketLengthMean = flowmetrics.BwdPacketLengthMean(flow.BwdPktStats)
	flow.BwdPacketLengthStd = flowmetrics.BwdPacketLengthStd(flow.BwdPktStats)
	flow.FlowBytesPerSecond = (float64(flow.TotalLengthofFwdPacket+flow.TotalLengthofBwdPacket) / (float64(flow.FlowDuration) / 1e6))
	flow.FlowPacketsPerSecond = (float64(flow.TotalfwdPackets+flow.TotalbwdPackets) / (float64(flow.FlowDuration) / 1e6))
	if flow.FlowDuration > 0 {
		seconds := float64(flow.FlowDuration) / 1e6
		flow.FwdPacketsPerSecond = float64(flow.TotalfwdPackets) / seconds
		flow.BwdPacketsPerSecond = float64(flow.TotalbwdPackets) / seconds
	} else {
		flow.FwdPacketsPerSecond = 0
		flow.BwdPacketsPerSecond = 0
	}

	flow.FlowIATMean = flowmetrics.FlowIATMean(flow.TotalfwdPackets+flow.TotalbwdPackets, flow.FlowIAT)
	flow.FlowIATStd = flowmetrics.FlowIATStd(flow.TotalfwdPackets+flow.TotalbwdPackets, flow.FlowIAT)
	flow.FlowIATMax = flowmetrics.FlowIATMax(flow.TotalfwdPackets+flow.TotalbwdPackets, flow.FlowIAT)
	flow.FlowIATMin = flowmetrics.FlowIATMin(flow.TotalfwdPackets+flow.TotalbwdPackets, flow.FlowIAT)

	if flow.PktLenStats.N() > 0 {
		flow.PktLenMin = flow.PktLenStats.Min()
		flow.PktLenMax = flow.PktLenStats.Max()
		flow.PktLenMean = flow.PktLenStats.Mean()
		flow.PktLenStd = flow.PktLenStats.StandardDeviation()
		flow.PktLenVar = flow.PktLenStats.Variance()
	} else {
		flow.PktLenMin = 0
		flow.PktLenMax = 0
		flow.PktLenMean = 0
		flow.PktLenStd = 0
		flow.PktLenVar = 0
	}

	flow.FwdIATTotal = flowmetrics.FwdIATTotal(flow.TotalfwdPackets, flow.FwdIAT)
	flow.FwdIATMean = flowmetrics.FwdIATMean(flow.TotalfwdPackets, flow.FwdIAT)
	flow.FwdIATStd = flowmetrics.FwdIATStd(flow.TotalfwdPackets, flow.FwdIAT)
	flow.FwdIATMax = flowmetrics.FwdIATMax(flow.TotalfwdPackets, flow.FwdIAT)
	flow.FwdIATMin = flowmetrics.FwdIATMin(flow.TotalfwdPackets, flow.FwdIAT)

	flow.BwdIATTotal = flowmetrics.BwdIATTotal(flow.TotalbwdPackets, flow.BwdIAT)
	flow.BwdIATMean = flowmetrics.BwdIATMean(flow.TotalbwdPackets, flow.BwdIAT)
	flow.BwdIATStd = flowmetrics.BwdIATStd(flow.TotalbwdPackets, flow.BwdIAT)
	flow.BwdIATMax = flowmetrics.BwdIATMax(flow.TotalbwdPackets, flow.BwdIAT)
	flow.BwdIATMin = flowmetrics.BwdIATMin(flow.TotalbwdPackets, flow.BwdIAT)

	record := []string{
		flow.Flowid.String(),
		flow.SrcIP,
		flow.SrcPort,
		flow.DstIP,
		flow.DstPort,
		strconv.Itoa(flow.Protocol),
		flow.Timestamp.Format(time.RFC3339Nano),
		strconv.FormatInt(flow.FlowDuration, 10),
		strconv.Itoa(flow.TotalfwdPackets),
		strconv.Itoa(flow.TotalbwdPackets),
		strconv.FormatInt(flow.TotalLengthofFwdPacket, 10),
		strconv.FormatInt(flow.TotalLengthofBwdPacket, 10),
		strconv.FormatFloat(flow.FwdPacketLengthMax, 'f', 6, 64),
		strconv.FormatFloat(flow.FwdPacketLengthMin, 'f', 6, 64),
		strconv.FormatFloat(flow.FwdPacketLengthMean, 'f', 6, 64),
		strconv.FormatFloat(flow.FwdPacketLengthStd, 'f', 6, 64),
		strconv.FormatFloat(flow.BwdPacketLengthMax, 'f', 6, 64),
		strconv.FormatFloat(flow.BwdPacketLengthMin, 'f', 6, 64),
		strconv.FormatFloat(flow.BwdPacketLengthMean, 'f', 6, 64),
		strconv.FormatFloat(flow.BwdPacketLengthStd, 'f', 6, 64),
		strconv.FormatFloat(flow.FlowBytesPerSecond, 'f', 6, 64),
		strconv.FormatFloat(flow.FlowPacketsPerSecond, 'f', 6, 64),
		strconv.FormatFloat(flow.FlowIATMean, 'f', 6, 64),
		strconv.FormatFloat(flow.FlowIATStd, 'f', 6, 64),
		strconv.FormatFloat(flow.FlowIATMax, 'f', 6, 64),
		strconv.FormatFloat(flow.FlowIATMin, 'f', 6, 64),
		strconv.FormatFloat(flow.FwdIATTotal, 'f', 6, 64),
		strconv.FormatFloat(flow.FwdIATMean, 'f', 6, 64),
		strconv.FormatFloat(flow.FwdIATStd, 'f', 6, 64),
		strconv.FormatFloat(flow.FwdIATMax, 'f', 6, 64),
		strconv.FormatFloat(flow.FwdIATMin, 'f', 6, 64),
		strconv.FormatFloat(flow.BwdIATTotal, 'f', 6, 64),
		strconv.FormatFloat(flow.BwdIATMean, 'f', 6, 64),
		strconv.FormatFloat(flow.BwdIATStd, 'f', 6, 64),
		strconv.FormatFloat(flow.BwdIATMax, 'f', 6, 64),
		strconv.FormatFloat(flow.BwdIATMin, 'f', 6, 64),
		strconv.Itoa(flow.FPSH_cnt),
		strconv.Itoa(flow.BPSH_cnt),
		strconv.Itoa(flow.FURG_cnt),
		strconv.Itoa(flow.BURG_cnt),
		strconv.FormatInt(flow.FwdHeaderLength, 10),
		strconv.FormatInt(flow.BwdHeaderLength, 10),
		strconv.FormatFloat(flow.FwdPacketsPerSecond, 'f', 6, 64),
		strconv.FormatFloat(flow.BwdPacketsPerSecond, 'f', 6, 64),
		strconv.FormatFloat(flow.PktLenMin, 'f', 6, 64),
		strconv.FormatFloat(flow.PktLenMax, 'f', 6, 64),
		strconv.FormatFloat(flow.PktLenMean, 'f', 6, 64),
		strconv.FormatFloat(flow.PktLenStd, 'f', 6, 64),
		strconv.FormatFloat(flow.PktLenVar, 'f', 6, 64),
		strconv.Itoa(flow.FINFlagCount),
		strconv.Itoa(flow.SYNFlagCount),
		strconv.Itoa(flow.RSTFlagCount),
		strconv.Itoa(flow.PSHFlagCount),
		strconv.Itoa(flow.ACKFlagCount),
		strconv.Itoa(flow.URGFlagCount),
		strconv.Itoa(flow.CWRFlagCount),
		strconv.Itoa(flow.ECEFlagCount),
	}

	AppendToCSV(writer, record)

	delete(flowmap, flowid)
}
func generateFlowID(packet gopacket.Packet) utils.Flowid {
	networkLayer := packet.NetworkLayer()
	transportLayer := packet.TransportLayer()

	srcIP, dstIP := "", ""
	srcPort, dstPort := "0", "0"
	protocol := 0

	if networkLayer != nil {
		srcIP = networkLayer.NetworkFlow().Src().String()
		dstIP = networkLayer.NetworkFlow().Dst().String()
	}

	if transportLayer != nil {
		if transportLayer.LayerType().String() == "TCP" {
			srcPort = transportLayer.TransportFlow().Src().String()
			dstPort = transportLayer.TransportFlow().Dst().String()
			protocol = 6
		} else if transportLayer.LayerType().String() == "UDP" {
			srcPort = transportLayer.TransportFlow().Src().String()
			dstPort = transportLayer.TransportFlow().Dst().String()
			protocol = 17
		}
	}

	return utils.Flowid{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Protocol: protocol,
	}
}

func generateReverseFlowID(packet gopacket.Packet) utils.Flowid {
	networkLayer := packet.NetworkLayer()
	transportLayer := packet.TransportLayer()

	srcIP, dstIP := "", ""
	srcPort, dstPort := "0", "0"
	protocol := 0

	if networkLayer != nil {
		srcIP = networkLayer.NetworkFlow().Src().String()
		dstIP = networkLayer.NetworkFlow().Dst().String()
	}

	if transportLayer != nil {
		if transportLayer.LayerType().String() == "TCP" {
			srcPort = transportLayer.TransportFlow().Src().String()
			dstPort = transportLayer.TransportFlow().Dst().String()
			protocol = 6
		} else if transportLayer.LayerType().String() == "UDP" {
			srcPort = transportLayer.TransportFlow().Src().String()
			dstPort = transportLayer.TransportFlow().Dst().String()
			protocol = 17
		}
	}

	return utils.Flowid{
		SrcIP:    dstIP,
		DstIP:    srcIP,
		SrcPort:  dstPort,
		DstPort:  srcPort,
		Protocol: protocol,
	}
}
