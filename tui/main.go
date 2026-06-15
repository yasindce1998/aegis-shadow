package main

import (
	"flag"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	defenseBin := flag.String("defense-bin", "defense", "Path to the defense binary")
	flag.Parse()

	m := initialModel()

	p := tea.NewProgram(m, tea.WithAltScreen())

	go func() {
		cmd := spawnDefense(*defenseBin, flag.Args())
		p.Send(cmd())
	}()

	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
