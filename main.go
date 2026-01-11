package main

import (
	"client/gui"
	"client/utils"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	choice, ok := runLauncherTUI()
	if !ok {
		return
	}

	if choice.mode == analysisModeLive {
		runLive(choice.device)
		return
	}

	runOffline(choice.pcapPath)
}

type analysisMode int

const (
	analysisModeLive analysisMode = iota
	analysisModeOffline
)

type launcherChoice struct {
	mode     analysisMode
	device   string
	pcapPath string
}

type launcherStage int

const (
	launcherStageMode launcherStage = iota
	launcherStageDevice
	launcherStageOfflinePath
)

type launcherModel struct {
	stage launcherStage

	modeIndex int

	devs       []pcap.Interface
	devIndex   int
	devsErr    error
	showDevs   bool
	deviceName string

	fileInput textinput.Model

	choice launcherChoice
	done   bool
}

func runLauncherTUI() (launcherChoice, bool) {
	m := newLauncherModel()
	p := tea.NewProgram(m)
	final, err := p.Run()
	if err != nil {
		fmt.Println("Error:", err)
		return launcherChoice{}, false
	}
	res := final.(launcherModel)
	if !res.done {
		return launcherChoice{}, false
	}
	return res.choice, true
}

func newLauncherModel() launcherModel {
	devs, devErr := pcap.FindAllDevs()
	input := textinput.New()
	input.Placeholder = "path/to/file.pcap"
	input.CharLimit = 512
	input.Width = 50

	return launcherModel{
		stage:     launcherStageMode,
		devs:      devs,
		devsErr:   devErr,
		fileInput: input,
	}
}

func (m launcherModel) Init() tea.Cmd {
	return nil
}

func (m launcherModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "b":
			switch m.stage {
			case launcherStageDevice, launcherStageOfflinePath:
				m.stage = launcherStageMode
				m.fileInput.Blur()
				return m, nil
			}
		}
	}

	switch m.stage {
	case launcherStageMode:
		return m.updateMode(msg)
	case launcherStageDevice:
		return m.updateDevice(msg)
	case launcherStageOfflinePath:
		return m.updateOfflinePath(msg)
	default:
		return m, nil
	}
}

func (m launcherModel) updateMode(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}

	switch key.String() {
	case "up", "k":
		if m.modeIndex > 0 {
			m.modeIndex--
		}
	case "down", "j":
		if m.modeIndex < 1 {
			m.modeIndex++
		}
	case "enter":
		if m.modeIndex == 0 {
			m.stage = launcherStageDevice
			return m, nil
		}
		m.stage = launcherStageOfflinePath
		m.fileInput.Focus()
		return m, nil
	}

	return m, nil
}

func (m launcherModel) updateDevice(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	if len(m.devs) == 0 {
		return m, nil
	}

	switch key.String() {
	case "up", "k":
		if m.devIndex > 0 {
			m.devIndex--
		}
	case "down", "j":
		if m.devIndex < len(m.devs)-1 {
			m.devIndex++
		}
	case "enter":
		m.choice = launcherChoice{mode: analysisModeLive, device: m.devs[m.devIndex].Name}
		m.done = true
		return m, tea.Quit
	}

	return m, nil
}

func (m launcherModel) updateOfflinePath(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	m.fileInput, cmd = m.fileInput.Update(msg)

	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "enter":
			path := strings.TrimSpace(m.fileInput.Value())
			if path == "" {
				return m, nil
			}
			// If user enters relative path, interpret it relative to CWD.
			if !filepath.IsAbs(path) {
				if cwd, err := os.Getwd(); err == nil {
					path = filepath.Join(cwd, path)
				}
			}
			m.choice = launcherChoice{mode: analysisModeOffline, pcapPath: path}
			m.done = true
			return m, tea.Quit
		}
	}

	return m, cmd
}

func (m launcherModel) View() string {
	var b strings.Builder
	b.WriteString("Simple Analysis Launcher\n\n")

	switch m.stage {
	case launcherStageMode:
		b.WriteString("Select mode (↑/↓, Enter)\n")
		b.WriteString("q: quit\n\n")
		modes := []string{"Live analysis", "Offline analysis"}
		for i, name := range modes {
			cursor := "  "
			if i == m.modeIndex {
				cursor = "> "
			}
			b.WriteString(cursor + name + "\n")
		}

	case launcherStageDevice:
		b.WriteString("Live analysis: select device (↑/↓, Enter)\n")
		b.WriteString("b: back   q: quit\n\n")
		if m.devsErr != nil {
			b.WriteString("Error listing devices: " + m.devsErr.Error() + "\n")
			return b.String()
		}
		if len(m.devs) == 0 {
			b.WriteString("No devices found.\n")
			return b.String()
		}
		for i, d := range m.devs {
			cursor := "  "
			if i == m.devIndex {
				cursor = "> "
			}
			label := d.Name
			if d.Description != "" {
				label += " - " + d.Description
			}
			b.WriteString(cursor + label + "\n")
		}

	case launcherStageOfflinePath:
		b.WriteString("Offline analysis: enter .pcap path\n")
		b.WriteString("Enter: start   b: back   q: quit\n\n")
		b.WriteString(m.fileInput.View())
		b.WriteString("\n")
	}

	return b.String()
}

func runLive(device string) {
	starttime := time.Now()

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
		"Fwd Bytes/Bulk Avg",
		"Fwd Packet/Bulk Avg",
		"Fwd Bulk Rate Avg",
		"Bwd Bytes/Bulk Avg",
		"Bwd Packet/Bulk Avg",
		"Bwd Bulk Rate Avg",
		"Subflow Fwd Packets",
		"Subflow Fwd Bytes",
		"Subflow Bwd Packets",
		"Subflow Bwd Bytes",
		"FWD Init Win Bytes",
		"Bwd Init Win Bytes",
		"Fwd Act Data Pkts",
		"Fwd Seg Size Min",
		"Active Mean",
		"Active Std",
		"Active Max",
		"Active Min",
		"Idle Mean",
		"Idle Std",
		"Idle Max",
		"Idle Min",
		"Label",
	}

	writer := InitCSVFile("out.csv", headers)
	defer CloseCSVFile(writer)

	packetcount := 0
	flowmap := make(map[utils.Flowid]*utils.Flow)
	var mu sync.Mutex
	var wg sync.WaitGroup
	ch := make(chan gopacket.Packet, 1000)
	wg.Add(1)
	go dispatchPacketToFlow(ch, flowmap, &wg, &mu, &packetcount, writer)

	if strings.TrimSpace(device) == "" {
		fmt.Println("No device selected")
		return
	}

	snapshotLen := int32(1600)
	promiscuous := true
	timeout := pcap.BlockForever

	handle, err := pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		fmt.Println("Error opening device:", err)
		return
	}

	fmt.Println("Listening on", device)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	captureDone := make(chan struct{})
	go func() {
		defer close(captureDone)
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
	}()

	// Run the existing dashboard TUI in the foreground; when it exits, stop capture.
	gui.Create()
	handle.Close()
	<-captureDone
	wg.Wait()

	fmt.Printf("Total Packets Processed: %d\n", packetcount)
	fmt.Printf("The Final Length Of Map Data : %d\n", len(flowmap))
	fmt.Printf("Processing completed in %s\n", time.Since(starttime))
}

func runOffline(inputPcapPath string) {
	starttime := time.Now()

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
		"Fwd Bytes/Bulk Avg",
		"Fwd Packet/Bulk Avg",
		"Fwd Bulk Rate Avg",
		"Bwd Bytes/Bulk Avg",
		"Bwd Packet/Bulk Avg",
		"Bwd Bulk Rate Avg",
		"Subflow Fwd Packets",
		"Subflow Fwd Bytes",
		"Subflow Bwd Packets",
		"Subflow Bwd Bytes",
		"FWD Init Win Bytes",
		"Bwd Init Win Bytes",
		"Fwd Act Data Pkts",
		"Fwd Seg Size Min",
		"Active Mean",
		"Active Std",
		"Active Max",
		"Active Min",
		"Idle Mean",
		"Idle Std",
		"Idle Max",
		"Idle Min",
		"Label",
	}

	writer := InitCSVFile("out.csv", headers)
	defer CloseCSVFile(writer)

	packetcount := 0
	flowmap := make(map[utils.Flowid]*utils.Flow)
	var mu sync.Mutex
	var wg sync.WaitGroup
	ch := make(chan gopacket.Packet, 1000)
	// One for the dispatcher goroutine.
	wg.Add(1)
	go dispatchPacketToFlow(ch, flowmap, &wg, &mu, &packetcount, writer)

	inputPcapPath = strings.TrimSpace(inputPcapPath)
	if inputPcapPath == "" {
		fmt.Println("No input PCAP path")
		close(ch)
		wg.Wait()
		return
	}
	if !strings.HasSuffix(strings.ToLower(inputPcapPath), ".pcap") {
		fmt.Println("Error: Input file must have a .pcap extension.")
		close(ch)
		wg.Wait()
		return
	}

	fmt.Printf("Input PCAP Path: %s\n", inputPcapPath)
	handle, err := pcap.OpenOffline(inputPcapPath)
	if err != nil {
		fmt.Println("Error opening PCAP file:", err)
		close(ch)
		wg.Wait()
		return
	}
	defer handle.Close()

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
	for id, flow := range flowmap {
		if flow != nil && (flow.TotalfwdPackets+flow.TotalbwdPackets) > 1 {
			flowComplete(id, flowmap, writer)
		} else {
			delete(flowmap, id)
		}
	}

	fmt.Printf("Total Packets Processed: %d\n", packetcount)
	fmt.Printf("The Final Length Of Map Data : %d\n", len(flowmap))
	fmt.Printf("Processing completed in %s\n", time.Since(starttime))
}
