package main

import (
	"client/utils"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	starttime := time.Now()

	if len(os.Args) != 3 {
		fmt.Println("Usage: go run main.go <input_pcap_path> <output_pcap_path>")
		return
	}

	input_pcap_path := os.Args[1]
	output_pcap_path := os.Args[2]

	if !strings.HasSuffix(input_pcap_path, ".pcap") && !strings.HasSuffix(output_pcap_path, ".csv") {
		fmt.Println("Error: Input file must have a .pcap extension and output file must have a .csv extension.")
		return
	}
	fmt.Printf("Input PCAP Path: %s\n", input_pcap_path)
	fmt.Printf("Output PCAP Path: %s\n", output_pcap_path)

	handle, err := pcap.OpenOffline(input_pcap_path)
	if err != nil {
		fmt.Println("Error opening PCAP file:", err)
		return
	}
	defer handle.Close()

	headers := []string{
		"Flow ID",
		"Src IP",
		"Src Port",
		"Dst IP",
		"Dst Port",
		"Protocol",
		"Timestamp",
		"Flow Duration",
		"Total Fwd Packet",
		"Total Bwd packets",
		"Total Length of Fwd Packet",
		"Total Length of Bwd Packet",
		"Fwd Packet Length Max",
		"Fwd Packet Length Min",
		"Fwd Packet Length Mean",
		"Fwd Packet Length Std",
		"Bwd Packet Length Max",
		"Bwd Packet Length Min",
		"Bwd Packet Length Mean",
		"Bwd Packet Length Std",
		"Flow Bytes/s",
		"Flow Packets/s",
		"Flow IAT Mean",
		"Flow IAT Std",
		"Flow IAT Max",
		"Flow IAT Min",
		"Fwd IAT Total",
		"Fwd IAT Mean",
		"Fwd IAT Std",
		"Fwd IAT Max",
		"Fwd IAT Min",
		"Bwd IAT Total",
		"Bwd IAT Mean",
		"Bwd IAT Std",
		"Bwd IAT Max",
		"Bwd IAT Min",
		"Fwd PSH Flags",
		"Bwd PSH Flags",
		"Fwd URG Flags",
		"Bwd URG Flags",
		"Fwd Header Length",
		"Bwd Header Length",
		"Fwd Packets/s",
		"Bwd Packets/s",
		"Packet Length Min",
		"Packet Length Max",
		"Packet Length Mean",
		"Packet Length Std",
		"Packet Length Variance",
		"FIN Flag Count",
		"SYN Flag Count",
		"RST Flag Count",
		"PSH Flag Count",
		"ACK Flag Count",
		"URG Flag Count",
		"CWR Flag Count",
		"ECE Flag Count",
		"Down/Up Ratio",
		"Average Packet Size",
		"Fwd Segment Size Avg",
		"Bwd Segment Size Avg",
	}
	writer := InitCSVFile(output_pcap_path, headers)
	defer CloseCSVFile(writer)

	packetcount := 0
	flowmap := make(map[utils.Flowid]*utils.Flow)
	var mu sync.Mutex
	var wg sync.WaitGroup
	ch := make(chan gopacket.Packet, 1000)
	wg.Add(1)
	go dispatchPacketToFlow(ch, flowmap, &wg, &mu, &packetcount, writer)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		networkLayer := packet.NetworkLayer()
		if networkLayer != nil {
			if networkLayer.NetworkFlow().EndpointType().String() == "IPv4" {
				wg.Add(1)
				ch <- packet
			}
		}
	}
	close(ch)
	wg.Wait()

	// End-of-file flush: emit any remaining flows that have >1 packet.
	// This matches CICFlowMeter behavior where flows may not end with FIN/RST
	// within the capture window.
	for id, flow := range flowmap {
		if flow != nil && (flow.TotalfwdPackets+flow.TotalbwdPackets) > 1 {
			flowComplete(id, flowmap, writer)
		} else {
			delete(flowmap, id)
		}
	}
	// for _, flow := range flowmap {
	// 	if flow.TotalfwdPackets > 0 {
	// 		fmt.Printf("FlowID: %s, FwdPackets: %d, BwdPackets: %d, FwdBytes: %d, BwdBytes: %d\n",
	// 			flow.Flowid.String(), flow.TotalfwdPackets, flow.TotalbwdPackets, flow.TotalfwdBytes, flow.TotalbwdBytes)
	// 	}
	// }
	fmt.Printf("Total Packets Processed: %d\n", packetcount)
	fmt.Printf("The Final Length Of Map Data : %d\n", len(flowmap))
	fmt.Printf("Processing completed in %s\n", time.Since(starttime))
}
