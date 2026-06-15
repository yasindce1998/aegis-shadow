package main

import (
	"bufio"
	"encoding/json"
	"io"
	"os/exec"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

type alertMsg Alert
type bridgeErrMsg struct{ err error }
type bridgeExitMsg struct{}

func spawnDefense(bin string, args []string) tea.Cmd {
	return func() tea.Msg {
		cmdArgs := append(args, "--json-stdout")
		cmd := exec.Command(bin, cmdArgs...)

		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return bridgeErrMsg{err}
		}
		cmd.Stderr = nil // let it inherit our stderr

		if err := cmd.Start(); err != nil {
			return bridgeErrMsg{err}
		}

		return bridgeStartedMsg{cmd: cmd, reader: stdout}
	}
}

type bridgeStartedMsg struct {
	cmd    *exec.Cmd
	reader io.ReadCloser
}

func readAlerts(reader io.Reader) tea.Cmd {
	return func() tea.Msg {
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 64*1024), 64*1024)

		if scanner.Scan() {
			var alert Alert
			if err := json.Unmarshal(scanner.Bytes(), &alert); err != nil {
				return bridgeErrMsg{err}
			}
			alert.ReceivedAt = time.Now()
			return alertMsg(alert)
		}

		if err := scanner.Err(); err != nil {
			return bridgeErrMsg{err}
		}
		return bridgeExitMsg{}
	}
}
