package gui

import (
	"client/utils"
	"fmt"
	"math/rand"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/lipgloss"
)

// --- Styles ---

var (
	// Colors
	subtle    = lipgloss.AdaptiveColor{Light: "#D9DCCF", Dark: "#383838"}
	highlight = lipgloss.AdaptiveColor{Light: "#874BFD", Dark: "#7D56F4"}
	special   = lipgloss.AdaptiveColor{Light: "#43BF6D", Dark: "#73F59F"}
	danger    = lipgloss.AdaptiveColor{Light: "#F25D94", Dark: "#F55246"}

	// General App
	appStyle = lipgloss.NewStyle().Margin(1, 1)

	// Borders & Panes
	paneStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(highlight).
			Padding(1).
			MarginRight(0)

	// List Styles
	listHeaderStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.NormalBorder()).
			BorderBottom(true).
			BorderForeground(subtle).
			Foreground(special).
			Bold(true).
			MarginBottom(1).
			Align(lipgloss.Center)

	listItemStyle = lipgloss.NewStyle().PaddingLeft(1)

	// Analysis/Dashboard Styles
	cardStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(subtle).
			Padding(1).
			MarginBottom(1)

	// Status Styles
	benignStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)  // Green
	attackStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true) // Red

	// Critical Alert
	criticalStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("255")).
			Background(lipgloss.Color("196")).
			Blink(true).
			Padding(0, 1).
			Align(lipgloss.Center)

	// Text Styles
	labelStyle   = lipgloss.NewStyle().Foreground(subtle)
	statValStyle = lipgloss.NewStyle().Foreground(special).Bold(true)
)

// --- Data Models ---

type RawRecord struct {
	FlowID  string
	SrcIP   string
	SrcPort string
	DstIP   string
	DstPort string
	Label   string
}

type ProcessedRecord struct {
	FlowID    string
	SrcIP     string
	SrcPort   string
	DstIP     string
	DstPort   string
	Timestamp time.Time

	IsAnalyzed bool
	Label      string
	IsBenign   bool
}

type newFlowMsg struct {
	FlowID    string
	SrcIP     string
	SrcPort   string
	DstIP     string
	DstPort   string
	Timestamp time.Time
}

var (
	programMu sync.RWMutex
	program   *tea.Program
)

// --- Messages ---

type tickMsg time.Time
type analysisResultMsg struct {
	FlowID string
	Label  string
}
type statsUpdateMsg struct{}

// --- Main Model ---

type model struct {
	records      []ProcessedRecord
	labelCounts  map[string]int
	totalRecords int

	// Stats
	cpuUsage    float64
	ramUsage    uint64
	riskPercent float64

	// UI Components
	spinner      spinner.Model
	listViewport viewport.Model
	cpuProgress  progress.Model
	ramProgress  progress.Model

	// Renderers
	glamourRenderer *glamour.TermRenderer

	// Dimensions
	width  int
	height int
}

func initialModel() model {
	// 1. Spinner for pending records
	s := spinner.New()
	s.Spinner = spinner.Pulse
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	// 2. Progress Bars
	cpuBar := progress.New(progress.WithGradient("#2774D4", "#5AD9F7"))
	ramBar := progress.New(progress.WithGradient("#6B29D6", "#E367E0"))

	// 3. Markdown Renderer
	r, _ := glamour.NewTermRenderer(
		glamour.WithAutoStyle(),
		glamour.WithWordWrap(45), // Slightly wider for table
	)

	return model{
		records:         make([]ProcessedRecord, 0),
		labelCounts:     make(map[string]int),
		spinner:         s,
		cpuProgress:     cpuBar,
		ramProgress:     ramBar,
		glamourRenderer: r,
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		statsTickGenerator(),
	)
}

// --- Update Loop ---

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var (
		cmd  tea.Cmd
		cmds []tea.Cmd
	)

	switch msg := msg.(type) {

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit
		}
		m.listViewport, cmd = m.listViewport.Update(msg)
		cmds = append(cmds, cmd)

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

		// Split screen: 60% List, 40% Analysis
		listWidth := int(float64(msg.Width) * 0.6)
		analysisWidth := msg.Width - listWidth - 6
		paneHeight := msg.Height - 4

		m.listViewport.Width = listWidth - 4
		m.listViewport.Height = paneHeight - 2 // space for header

		m.cpuProgress.Width = analysisWidth - 10
		m.ramProgress.Width = analysisWidth - 10

		m.listViewport.SetContent(m.renderList())

	case spinner.TickMsg:
		m.spinner, cmd = m.spinner.Update(msg)
		m.listViewport.SetContent(m.renderList()) // update spinner in list
		cmds = append(cmds, cmd)

	case tickMsg:
		// No-op: demo tick generator removed.

	case newFlowMsg:
		newRec := ProcessedRecord{
			FlowID:     msg.FlowID,
			SrcIP:      msg.SrcIP,
			SrcPort:    msg.SrcPort,
			DstIP:      msg.DstIP,
			DstPort:    msg.DstPort,
			Timestamp:  msg.Timestamp,
			IsAnalyzed: false,
		}

		m.records = append(m.records, newRec)
		if len(m.records) > 1000 {
			m.records = m.records[1:]
		}
		m.totalRecords++

		m.listViewport.SetContent(m.renderList())
		m.listViewport.GotoBottom()
		// Labeling is pushed from the flow pipeline via UpdateLabelInTui.

	case analysisResultMsg:
		found := false
		for i := len(m.records) - 1; i >= 0; i-- {
			if m.records[i].FlowID == msg.FlowID && !m.records[i].IsAnalyzed {
				m.records[i].Label = msg.Label
				m.records[i].IsAnalyzed = true
				m.records[i].IsBenign = (msg.Label == "BENIGN")
				found = true
				break
			}
		}
		if found {
			m.labelCounts[msg.Label]++
			m.listViewport.SetContent(m.renderList())
		}

	case statsUpdateMsg:
		// Hardware Stats
		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)
		m.ramUsage = memStats.Alloc / 1024 / 1024

		// Logic: More attacks = Higher CPU simulation
		totalAnalyzed := 0
		attacks := 0
		for _, count := range m.labelCounts {
			totalAnalyzed += count
		}
		for lbl, count := range m.labelCounts {
			if lbl != "BENIGN" {
				attacks += count
			}
		}

		m.riskPercent = 0.0
		if totalAnalyzed > 0 {
			m.riskPercent = (float64(attacks) / float64(totalAnalyzed)) * 100
		}

		// CPU Drift
		targetCpu := 10.0 + (m.riskPercent / 2.0)
		m.cpuUsage = targetCpu + (rand.Float64() * 5.0)

		cmds = append(cmds, statsTickGenerator())
	}

	return m, tea.Batch(cmds...)
}

// --- View Rendering ---

func (m model) View() string {
	if m.width == 0 {
		return "Initializing Dashboard..."
	}

	// 1. LEFT PANE: Network Traffic List
	listHeader := listHeaderStyle.Width(m.listViewport.Width).Render("LIVE TRAFFIC FEED")
	listView := paneStyle.
		Width(m.listViewport.Width + 2).
		Height(m.height - 2).
		Render(lipgloss.JoinVertical(lipgloss.Left, listHeader, m.listViewport.View()))

	// 2. RIGHT PANE: Analysis Dashboard
	analysisContent := m.renderDashboard()
	analysisView := paneStyle.
		Width(m.width - m.listViewport.Width - 6).
		Height(m.height - 2).
		Render(analysisContent)

	return appStyle.Render(lipgloss.JoinHorizontal(lipgloss.Top, listView, analysisView))
}

func (m model) renderList() string {
	var s strings.Builder
	for _, r := range m.records {
		var icon, label, ipInfo string

		ipInfo = fmt.Sprintf("%-15s:%-5s → %-15s:%-5s", r.SrcIP, r.SrcPort, r.DstIP, r.DstPort)

		if !r.IsAnalyzed {
			icon = m.spinner.View()
			label = lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("SCANNING...")
		} else {
			if r.IsBenign {
				icon = benignStyle.Render("✔")
				label = benignStyle.Render("BENIGN")
			} else {
				icon = attackStyle.Render("✖")
				label = attackStyle.Render(r.Label)
			}
		}

		line := fmt.Sprintf("%s  %s  %s", icon, ipInfo, label)
		s.WriteString(listItemStyle.Render(line) + "\n")
	}
	return s.String()
}

func (m model) renderDashboard() string {
	// --- A. System Risk Header ---
	var riskHeader string
	if m.riskPercent > 30.0 {
		riskHeader = criticalStyle.Render("⚠ CRITICAL RISK DETECTED ⚠")
	} else if m.riskPercent > 10.0 {
		riskHeader = lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Bold(true).Render("⚠ MODERATE RISK")
	} else {
		riskHeader = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true).Render("✔ SYSTEM SECURE")
	}

	// --- B. Hardware Stats ---
	cpuPct := m.cpuUsage / 100.0
	if cpuPct > 1.0 {
		cpuPct = 1.0
	}
	cpuBarView := m.cpuProgress.ViewAs(cpuPct)
	cpuLabel := labelStyle.Render("CPU Load")

	ramPct := float64(m.ramUsage) / 512.0
	if ramPct > 1.0 {
		ramPct = 1.0
	}
	ramBarView := m.ramProgress.ViewAs(ramPct)
	ramLabel := labelStyle.Render(fmt.Sprintf("RAM Usage (%d MB)", m.ramUsage))

	statsBox := cardStyle.Render(
		lipgloss.JoinVertical(lipgloss.Left,
			lipgloss.JoinHorizontal(lipgloss.Center, cpuLabel, "  ", statValStyle.Render(fmt.Sprintf("%.1f%%", m.cpuUsage))),
			cpuBarView,
			"\n",
			lipgloss.JoinHorizontal(lipgloss.Center, ramLabel),
			ramBarView,
		),
	)

	// --- C. Attack Distribution Table ---

	// 1. Calculate Stats
	totalAnalyzed := 0
	for _, count := range m.labelCounts {
		totalAnalyzed += count
	}

	// 2. Prepare Data Structure for Sorting
	type threatStat struct {
		Label string
		Count int
		Pct   float64
	}
	var stats []threatStat

	topThreat := "None"
	maxCount := 0

	for lbl, count := range m.labelCounts {
		// Find Top Threat
		if lbl != "BENIGN" && count > maxCount {
			maxCount = count
			topThreat = lbl
		}

		// Calculate Pct
		pct := 0.0
		if totalAnalyzed > 0 {
			pct = (float64(count) / float64(totalAnalyzed)) * 100
		}
		stats = append(stats, threatStat{lbl, count, pct})
	}

	// 3. Sort by Count Descending
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Count > stats[j].Count
	})

	// 4. Build Markdown Table
	tableStr := "| Label | % | Count |\n| --- | --- | --- |\n"
	for _, s := range stats {
		// Highlight non-benign rows in bold or separate char if possible,
		// but standard markdown table is safest here.
		tableStr += fmt.Sprintf("| %s | %.1f%% | %d |\n", s.Label, s.Pct, s.Count)
	}

	// 5. Combine Text
	threatInfo := fmt.Sprintf(`
**Attack Frequency:** %.1f%%
**Top Threat:** %s

### Threat Breakdown
%s
`, m.riskPercent, topThreat, tableStr)

	renderedThreats, _ := m.glamourRenderer.Render(threatInfo)

	// Combine Dashboard Elements
	return lipgloss.JoinVertical(
		lipgloss.Center,
		riskHeader,
		"\n",
		statsBox,
		renderedThreats,
	)
}

// --- Helpers ---

func statsTickGenerator() tea.Cmd {
	return tea.Tick(time.Millisecond*500, func(t time.Time) tea.Msg {
		return statsUpdateMsg{}
	})
}

func sendToProgram(msg tea.Msg) {
	programMu.RLock()
	p := program
	programMu.RUnlock()
	if p == nil {
		return
	}
	p.Send(msg)
}

func AddFlowToTui(flow *utils.Flow) {
	if flow == nil {
		return
	}
	sendToProgram(newFlowMsg{
		FlowID:    flow.Flowid.String(),
		SrcIP:     flow.SrcIP,
		SrcPort:   flow.SrcPort,
		DstIP:     flow.DstIP,
		DstPort:   flow.DstPort,
		Timestamp: flow.LastSeenTime,
	})
}

func UpdateLabelInTui(flowID string, label string) {
	if flowID == "" {
		return
	}
	sendToProgram(analysisResultMsg{FlowID: flowID, Label: label})
}

func Create() {
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	programMu.Lock()
	program = p
	programMu.Unlock()

	if _, err := p.Run(); err != nil {
		fmt.Println("Error:", err)
	}

	programMu.Lock()
	program = nil
	programMu.Unlock()
}
