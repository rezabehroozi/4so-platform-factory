package daemoncli

import (
	"fmt"
	"strings"
)

type Action string

const (
	Run     Action = "run"
	Help    Action = "help"
	Version Action = "version"
)

// Parse accepts only the explicit side-effect-free daemon CLI surface. Runtime
// configuration is environment-driven, so silently ignoring argv would turn
// operator typos into real daemon execution.
func Parse(args []string) (Action, error) {
	if len(args) == 0 {
		return Run, nil
	}
	if len(args) == 1 {
		switch strings.TrimSpace(args[0]) {
		case "help", "--help", "-h":
			return Help, nil
		case "version", "--version":
			return Version, nil
		}
	}
	return "", fmt.Errorf("unsupported arguments: %s", strings.Join(args, " "))
}

func Usage(binary string) string {
	return fmt.Sprintf("usage: %s [--help|--version]", strings.TrimSpace(binary))
}
