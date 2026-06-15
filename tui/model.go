package main

import (
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type filterLevel int

const (
	filterAll filterLevel = iota
	filterHigh
	filterCritical
)

type model struct {
	alerts     *AlertRing
	cursor     int
	autoScroll bool
	filter     filterLevel
	chainsOnly bool
	startTime  time.Time
	width      int
	height     int
	quitting   bool

	// bridge
	cmd    *exec.Cmd
	reader io.ReadCloser

	// metrics
	totalAlerts      int
	chainCount       int
	suppressedCount  int
	errMsg           string
}

func initialModel() model {
	return model{
		alerts:     NewAlertRing(1000),
		autoScroll: true,
		startTime:  time.Now(),
		width:      80,
		height:     24,
	}
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			if m.cmd != nil {
				_ = m.cmd.Process.Kill()
			}
			return m, tea.Quit
		case "j", "down":
			if m.cursor < m.alerts.Len()-1 {
				m.cursor++
				m.autoScroll = false
			}
		case "k", "up":
			if m.cursor > 0 {
				m.cursor--
				m.autoScroll = false
			}
		case "p":
			m.autoScroll = !m.autoScroll
		case "t":
			m.filter = (m.filter + 1) % 3
		case "c":
			m.chainsOnly = !m.chainsOnly
		case "G":
			m.cursor = m.alerts.Len() - 1
			m.autoScroll = true
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case bridgeStartedMsg:
		m.cmd = msg.cmd
		m.reader = msg.reader
		return m, readAlerts(msg.reader)

	case alertMsg:
		alert := Alert(msg)
		m.alerts.Push(alert)
		m.totalAlerts++
		if alert.IsAttackChain {
			m.chainCount++
		}
		if m.autoScroll {
			m.cursor = m.alerts.Len() - 1
		}
		return m, readAlerts(m.reader)

	case bridgeErrMsg:
		m.errMsg = msg.err.Error()
		return m, nil

	case bridgeExitMsg:
		m.errMsg = "defense process exited"
		return m, nil
	}

	return m, nil
}

func (m model) View() string {
	if m.quitting {
		return ""
	}

	var b strings.Builder

	// Header
	uptime := time.Since(m.startTime).Truncate(time.Second)
	header := headerStyle.Width(m.width).Render(
		fmt.Sprintf(" Aegis-Shadow Defense Monitor %s %s",
			strings.Repeat("─", max(0, m.width-52)),
			uptime,
		),
	)
	b.WriteString(header)
	b.WriteString("\n")

	// Metrics bar
	filterStr := [...]string{"ALL", "HIGH+", "CRIT"}
	metrics := metricsStyle.Width(m.width).Render(
		fmt.Sprintf(" Alerts: %d │ Chains: %d │ Filter: %s │ AutoScroll: %v",
			m.totalAlerts, m.chainCount, filterStr[m.filter], m.autoScroll,
		),
	)
	b.WriteString(metrics)
	b.WriteString("\n")

	// Table header
	tableHeader := tableHeaderStyle.Width(m.width).Render(
		fmt.Sprintf(" %-8s │ %-18s │ %-6s │ %-5s │ %-5s │ %s",
			"TIME", "TYPE", "PID", "SEV", "SCORE", "CHAIN"),
	)
	b.WriteString(tableHeader)
	b.WriteString("\n")

	// Table rows
	items := m.filteredAlerts()
	tableHeight := m.height - 8 // header + metrics + tableheader + details + border
	if tableHeight < 3 {
		tableHeight = 3
	}

	start := 0
	if len(items) > tableHeight {
		start = m.cursor - tableHeight/2
		if start < 0 {
			start = 0
		}
		if start+tableHeight > len(items) {
			start = len(items) - tableHeight
		}
	}
	end := start + tableHeight
	if end > len(items) {
		end = len(items)
	}

	for i := start; i < end; i++ {
		a := items[i]
		ts := a.ReceivedAt.Format("15:04:05")
		chain := " "
		if a.IsAttackChain {
			chain = "✓"
		}
		row := fmt.Sprintf(" %-8s │ %-18s │ %-6d │ %-5s │ %5.1f │ %s",
			ts, truncate(a.AlertType, 18), a.PID, a.Severity, a.AnomalyScore, chain)

		if i == m.cursor {
			b.WriteString(selectedStyle.Width(m.width).Render(row))
		} else {
			b.WriteString(rowStyle.Width(m.width).Render(row))
		}
		b.WriteString("\n")
	}

	// Details pane
	b.WriteString(separatorStyle.Width(m.width).Render(strings.Repeat("─", m.width)))
	b.WriteString("\n")
	if m.cursor >= 0 && m.cursor < len(items) {
		a := items[m.cursor]
		detail := fmt.Sprintf(" %s — pid=%d context=0x%x", a.AlertType, a.PID, a.Context)
		b.WriteString(detailStyle.Width(m.width).Render(detail))
		b.WriteString("\n")
		if len(a.CorrelatedTypes) > 0 {
			corr := fmt.Sprintf(" Correlated: %s", strings.Join(a.CorrelatedTypes, ", "))
			b.WriteString(detailStyle.Width(m.width).Render(corr))
		}
	}

	if m.errMsg != "" {
		b.WriteString("\n")
		b.WriteString(errStyle.Render(" Error: " + m.errMsg))
	}

	return b.String()
}

func (m model) filteredAlerts() []Alert {
	items := m.alerts.Items()
	if m.filter == filterAll && !m.chainsOnly {
		return items
	}

	filtered := make([]Alert, 0, len(items))
	for _, a := range items {
		if m.chainsOnly && !a.IsAttackChain {
			continue
		}
		switch m.filter {
		case filterHigh:
			if a.Severity != "HIGH" && a.Severity != "CRITICAL" {
				continue
			}
		case filterCritical:
			if a.Severity != "CRITICAL" {
				continue
			}
		}
		filtered = append(filtered, a)
	}
	return filtered
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Styles
var (
	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("39"))

	metricsStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("246"))

	tableHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("252"))

	selectedStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("236")).
			Foreground(lipgloss.Color("214"))

	rowStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("252"))

	separatorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("240"))

	detailStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("249"))

	errStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("196")).
			Bold(true)
)
