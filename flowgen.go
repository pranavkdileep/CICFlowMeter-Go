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
	// CICFlowMeter-like activity timeout used to segment Active/Idle periods.
	flowActivityTimeOutMicros := int64((5 * time.Second).Microseconds())

	updateForwardBulk := func(flow *utils.Flow, size int64, tsMicros int64) {
		if flow == nil {
			return
		}
		// If the other direction bulk advanced after our helper started, reset the helper.
		if flow.BwdLastBulkTS > flow.FwdBulkStartHelper {
			flow.FwdBulkStartHelper = 0
		}
		if size <= 0 {
			return
		}

		if flow.FwdBulkStartHelper == 0 {
			flow.FwdBulkStartHelper = tsMicros
			flow.FwdBulkPacketCountHelper = 1
			flow.FwdBulkSizeHelper = size
			flow.FwdLastBulkTS = tsMicros
			return
		}

		// Too much idle time between bulk packets? (> 1s)
		if float64(tsMicros-flow.FwdLastBulkTS)/1e6 > 1.0 {
			flow.FwdBulkStartHelper = tsMicros
			flow.FwdLastBulkTS = tsMicros
			flow.FwdBulkPacketCountHelper = 1
			flow.FwdBulkSizeHelper = size
			return
		}

		flow.FwdBulkPacketCountHelper++
		flow.FwdBulkSizeHelper += size

		// New bulk starts when helper count reaches 4 packets.
		if flow.FwdBulkPacketCountHelper == 4 {
			flow.FwdBulkStateCount++
			flow.FwdBulkPacketCount += flow.FwdBulkPacketCountHelper
			flow.FwdBulkSizeTotal += flow.FwdBulkSizeHelper
			flow.FwdBulkDuration += tsMicros - flow.FwdBulkStartHelper
		} else if flow.FwdBulkPacketCountHelper > 4 {
			// Continuation of existing bulk.
			flow.FwdBulkPacketCount += 1
			flow.FwdBulkSizeTotal += size
			flow.FwdBulkDuration += tsMicros - flow.FwdLastBulkTS
		}
		flow.FwdLastBulkTS = tsMicros
	}

	updateBackwardBulk := func(flow *utils.Flow, size int64, tsMicros int64) {
		if flow == nil {
			return
		}
		if flow.FwdLastBulkTS > flow.BwdBulkStartHelper {
			flow.BwdBulkStartHelper = 0
		}
		if size <= 0 {
			return
		}

		if flow.BwdBulkStartHelper == 0 {
			flow.BwdBulkStartHelper = tsMicros
			flow.BwdBulkPacketCountHelper = 1
			flow.BwdBulkSizeHelper = size
			flow.BwdLastBulkTS = tsMicros
			return
		}

		if float64(tsMicros-flow.BwdLastBulkTS)/1e6 > 1.0 {
			flow.BwdBulkStartHelper = tsMicros
			flow.BwdLastBulkTS = tsMicros
			flow.BwdBulkPacketCountHelper = 1
			flow.BwdBulkSizeHelper = size
			return
		}

		flow.BwdBulkPacketCountHelper++
		flow.BwdBulkSizeHelper += size

		if flow.BwdBulkPacketCountHelper == 4 {
			flow.BwdBulkStateCount++
			flow.BwdBulkPacketCount += flow.BwdBulkPacketCountHelper
			flow.BwdBulkSizeTotal += flow.BwdBulkSizeHelper
			flow.BwdBulkDuration += tsMicros - flow.BwdBulkStartHelper
		} else if flow.BwdBulkPacketCountHelper > 4 {
			flow.BwdBulkPacketCount += 1
			flow.BwdBulkSizeTotal += size
			flow.BwdBulkDuration += tsMicros - flow.BwdLastBulkTS
		}
		flow.BwdLastBulkTS = tsMicros
	}

	addPacket := func(flow *utils.Flow, packet gopacket.Packet, isForward bool, ts time.Time) {
		size := utils.GetPacketSize(packet)
		headerBytes := utils.GetTransportHeaderBytes(packet)
		tsMicros := ts.UnixMicro()

		// Active/Idle tracking must happen on every packet timestamp.
		utils.UpdateActiveIdleTime(flow, tsMicros, flowActivityTimeOutMicros)

		// Capture TCP window size for initial window bytes (like CICFlowMeter)
		if flow.Protocol == 6 {
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				if tcp, ok := tcpLayer.(*layers.TCP); ok {
					if isForward && flow.TotalfwdPackets == 0 {
						// First forward packet sets forward init window bytes
						flow.InitWinBytesForward = int(tcp.Window)
					} else if !isForward {
						// Backward packets set/update backward init window bytes
						flow.InitWinBytesBackward = int(tcp.Window)
					}
				}
			}
		}

		// CICFlowMeter: forward active data packets count (TCP only) and forward min segment size.
		if isForward {
			// min_seg_size_forward is min over packet.getHeaderBytes() in forward direction.
			if flow.TotalfwdPackets == 0 {
				flow.FwdSegSizeMin = headerBytes
			} else if headerBytes != 0 && (flow.FwdSegSizeMin == 0 || headerBytes < flow.FwdSegSizeMin) {
				flow.FwdSegSizeMin = headerBytes
			}

			// Act_data_pkt_forward increments when TCP payload bytes >= 1.
			if flow.Protocol == 6 && size >= 1 {
				flow.FwdActDataPkts++
			}
		}

		// Subflow detection (CICFlowMeter-like): increment sfCount when the gap between packets exceeds 1 second.
		if flow.SFLastPacketTS == 0 {
			flow.SFLastPacketTS = tsMicros
			flow.SFAcHelperTS = tsMicros
		} else {
			if float64(tsMicros-flow.SFLastPacketTS)/1e6 > 1.0 {
				flow.SFCount++
				flow.SFAcHelperTS = tsMicros
			}
			flow.SFLastPacketTS = tsMicros
		}
		flow.PktLenStats.AddValue(float64(size))

		// Bulk tracking (CICFlowMeter-like), per direction.
		if isForward {
			updateForwardBulk(flow, size, tsMicros)
		} else {
			updateBackwardBulk(flow, size, tsMicros)
		}

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
		tsMicros := ts.UnixMicro()
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
			FlowActive:             flowmetrics.NewStats(),
			FlowIdle:               flowmetrics.NewStats(),
			TotalLengthofFwdPacket: 0,
			TotalLengthofBwdPacket: 0,
			Timestamp:              ts,
			LastSeenTime:           ts,
			FwdLastSeenTime:        time.Time{},
			BwdLastSeenTime:        time.Time{},
			StartActiveTimeMicros:  tsMicros,
			EndActiveTimeMicros:    tsMicros,
		}
	}

	newFlowForFirstPacket := func(flowID utils.Flowid, ts time.Time) *utils.Flow {
		tsMicros := ts.UnixMicro()
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
			FlowActive:             flowmetrics.NewStats(),
			FlowIdle:               flowmetrics.NewStats(),
			TotalLengthofFwdPacket: 0,
			TotalLengthofBwdPacket: 0,
			Timestamp:              ts,
			LastSeenTime:           ts,
			FwdLastSeenTime:        ts,
			StartActiveTimeMicros:  tsMicros,
			EndActiveTimeMicros:    tsMicros,
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

	// Finalize the last active period for Active* metrics.
	utils.EndActiveIdleTime(flow)

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

	if flow.TotalfwdPackets > 0 {
		flow.DownUpRatio = float64(flow.TotalbwdPackets / flow.TotalfwdPackets)
	} else {
		flow.DownUpRatio = 0
	}

	// Segment size averages (CIC/Java logic): sum of per-packet sizes / packet count, per direction.
	if flow.TotalfwdPackets > 0 {
		flow.FwdSegSizeAvg = flow.FwdPktStats.Sum() / float64(flow.TotalfwdPackets)
	} else {
		flow.FwdSegSizeAvg = 0
	}
	if flow.TotalbwdPackets > 0 {
		flow.BwdSegSizeAvg = flow.BwdPktStats.Sum() / float64(flow.TotalbwdPackets)
	} else {
		flow.BwdSegSizeAvg = 0
	}

	// Bulk averages (integer division semantics, matching CICFlowMeter Java getters).
	if flow.FwdBulkStateCount != 0 {
		flow.FwdBytesPerBulkAvg = flow.FwdBulkSizeTotal / flow.FwdBulkStateCount
		flow.FwdPacketsPerBulkAvg = flow.FwdBulkPacketCount / flow.FwdBulkStateCount
	} else {
		flow.FwdBytesPerBulkAvg = 0
		flow.FwdPacketsPerBulkAvg = 0
	}
	if flow.FwdBulkDuration != 0 {
		flow.FwdBulkRateAvg = int64(float64(flow.FwdBulkSizeTotal) / (float64(flow.FwdBulkDuration) / 1e6))
	} else {
		flow.FwdBulkRateAvg = 0
	}

	if flow.BwdBulkStateCount != 0 {
		flow.BwdBytesPerBulkAvg = flow.BwdBulkSizeTotal / flow.BwdBulkStateCount
		flow.BwdPacketsPerBulkAvg = flow.BwdBulkPacketCount / flow.BwdBulkStateCount
	} else {
		flow.BwdBytesPerBulkAvg = 0
		flow.BwdPacketsPerBulkAvg = 0
	}
	if flow.BwdBulkDuration != 0 {
		flow.BwdBulkRateAvg = int64(float64(flow.BwdBulkSizeTotal) / (float64(flow.BwdBulkDuration) / 1e6))
	} else {
		flow.BwdBulkRateAvg = 0
	}

	// Subflow averages (integer division semantics like CICFlowMeter Java getters).
	if flow.SFCount > 0 {
		flow.SubflowFwdPkts = int64(flow.TotalfwdPackets) / flow.SFCount
		flow.SubflowFwdBytes = flow.TotalLengthofFwdPacket / flow.SFCount
		flow.SubflowBwdPkts = int64(flow.TotalbwdPackets) / flow.SFCount
		flow.SubflowBwdBytes = flow.TotalLengthofBwdPacket / flow.SFCount
	} else {
		flow.SubflowFwdPkts = 0
		flow.SubflowFwdBytes = 0
		flow.SubflowBwdPkts = 0
		flow.SubflowBwdBytes = 0
	}

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
		strconv.FormatFloat(flow.DownUpRatio, 'f', 6, 64),
		strconv.FormatFloat(flow.PktLenMean, 'f', 6, 64),
		strconv.FormatFloat(flow.FwdSegSizeAvg, 'f', 6, 64),
		strconv.FormatFloat(flow.BwdSegSizeAvg, 'f', 6, 64),
		strconv.FormatInt(flow.FwdBytesPerBulkAvg, 10),
		strconv.FormatInt(flow.FwdPacketsPerBulkAvg, 10),
		strconv.FormatInt(flow.FwdBulkRateAvg, 10),
		strconv.FormatInt(flow.BwdBytesPerBulkAvg, 10),
		strconv.FormatInt(flow.BwdPacketsPerBulkAvg, 10),
		strconv.FormatInt(flow.BwdBulkRateAvg, 10),
		strconv.FormatInt(flow.SubflowFwdPkts, 10),
		strconv.FormatInt(flow.SubflowFwdBytes, 10),
		strconv.FormatInt(flow.SubflowBwdPkts, 10),
		strconv.FormatInt(flow.SubflowBwdBytes, 10),
		strconv.Itoa(flow.InitWinBytesForward),
		strconv.Itoa(flow.InitWinBytesBackward),
		strconv.FormatInt(flow.FwdActDataPkts, 10),
		strconv.FormatInt(flow.FwdSegSizeMin, 10),
		strconv.FormatFloat(flow.FlowActive.Mean(), 'f', 6, 64),
		strconv.FormatFloat(flow.FlowActive.StandardDeviation(), 'f', 6, 64),
		strconv.FormatFloat(flow.FlowActive.Max(), 'f', 6, 64),
		strconv.FormatFloat(flow.FlowActive.Min(), 'f', 6, 64),
		strconv.FormatFloat(flow.FlowIdle.Mean(), 'f', 6, 64),
		strconv.FormatFloat(flow.FlowIdle.StandardDeviation(), 'f', 6, 64),
		strconv.FormatFloat(flow.FlowIdle.Max(), 'f', 6, 64),
		strconv.FormatFloat(flow.FlowIdle.Min(), 'f', 6, 64),
		"Sys",
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
