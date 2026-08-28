package bootstrap

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"platform.4so.io/factory/internal/durablefile"
)

type System interface {
	MkdirAll(string, fs.FileMode) error
	WriteFile(string, []byte, fs.FileMode) error
	CopyFile(string, string, fs.FileMode) error
	Run(context.Context, string, []string, map[string]string) error
	RunInput(context.Context, string, []string, map[string]string, io.Reader) error
	Output(context.Context, string, []string, map[string]string) ([]byte, error)
	Exists(string) bool
	IsRoot() bool
}

type LocalSystem struct{}

func (LocalSystem) MkdirAll(path string, mode fs.FileMode) error { return os.MkdirAll(path, mode) }
func (LocalSystem) WriteFile(path string, data []byte, mode fs.FileMode) error {
	return durablefile.Replace(path, data, 0o755, mode)
}
func (LocalSystem) CopyFile(source, destination string, mode fs.FileMode) error {
	raw, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	return LocalSystem{}.WriteFile(destination, raw, mode)
}
func (LocalSystem) Remove(path string) error { return os.Remove(path) }
func (system LocalSystem) Run(ctx context.Context, name string, args []string, environment map[string]string) error {
	_, err := system.Output(ctx, name, args, environment)
	return err
}
func (LocalSystem) RunInput(ctx context.Context, name string, args []string, environment map[string]string, input io.Reader) error {
	command := exec.CommandContext(ctx, name, args...)
	command.Env = os.Environ()
	for key, value := range environment {
		command.Env = append(command.Env, key+"="+value)
	}
	command.Stdin = input
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("run %s: %w: %s", name, err, string(output))
	}
	return nil
}
func (LocalSystem) OutputInput(ctx context.Context, name string, args []string, environment map[string]string, input io.Reader) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Env = os.Environ()
	for key, value := range environment {
		command.Env = append(command.Env, key+"="+value)
	}
	command.Stdin = input
	output, err := command.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("run %s: %w: %s", name, err, string(output))
	}
	return output, nil
}
func (LocalSystem) Output(ctx context.Context, name string, args []string, environment map[string]string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Env = os.Environ()
	for key, value := range environment {
		command.Env = append(command.Env, key+"="+value)
	}
	output, err := command.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("run %s: %w: %s", name, err, string(output))
	}
	return output, nil
}
func (LocalSystem) Exists(path string) bool { _, err := os.Stat(path); return err == nil }
func (LocalSystem) IsRoot() bool            { return os.Geteuid() == 0 }

type SimulatedSystem struct {
	Root     string
	Commands []string
}

func (s *SimulatedSystem) path(path string) string {
	clean := filepath.Clean("/" + path)
	return filepath.Join(s.Root, clean)
}
func (s *SimulatedSystem) MkdirAll(path string, mode fs.FileMode) error {
	return os.MkdirAll(s.path(path), mode)
}
func (s *SimulatedSystem) WriteFile(path string, data []byte, mode fs.FileMode) error {
	target := s.path(path)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	return os.WriteFile(target, data, mode)
}
func (s *SimulatedSystem) CopyFile(source, destination string, mode fs.FileMode) error {
	raw, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	return s.WriteFile(destination, raw, mode)
}
func (s *SimulatedSystem) Remove(path string) error { return os.Remove(s.path(path)) }
func (s *SimulatedSystem) Run(ctx context.Context, name string, args []string, environment map[string]string) error {
	_, err := s.Output(ctx, name, args, environment)
	return err
}
func (s *SimulatedSystem) RunInput(_ context.Context, name string, args []string, _ map[string]string, input io.Reader) error {
	s.Commands = append(s.Commands, fmt.Sprintf("%s %v <stdin>", name, args))
	if input != nil {
		_, _ = io.Copy(io.Discard, input)
	}
	return nil
}
func (s *SimulatedSystem) OutputInput(_ context.Context, name string, args []string, _ map[string]string, input io.Reader) ([]byte, error) {
	s.Commands = append(s.Commands, fmt.Sprintf("%s %v <stdin>", name, args))
	if input != nil {
		_, _ = io.Copy(io.Discard, input)
	}
	return nil, nil
}
func (s *SimulatedSystem) Output(_ context.Context, name string, args []string, _ map[string]string) ([]byte, error) {
	s.Commands = append(s.Commands, fmt.Sprintf("%s %v", name, args))
	if name == "systemctl" && len(args) > 0 && args[len(args)-1] == "rke2-server" {
		_ = s.WriteFile("/etc/rancher/rke2/rke2.yaml", []byte("apiVersion: v1\nkind: Config\n"), 0o600)
	}
	if name == "curl" && len(args) > 0 {
		for _, arg := range args {
			if strings.HasSuffix(arg, "/api/v1/organizations") {
				return []byte("[]"), nil
			}
		}
	}
	return nil, nil
}
func (s *SimulatedSystem) Exists(path string) bool {
	_, err := os.Stat(s.path(path))
	return err == nil
}
func (s *SimulatedSystem) IsRoot() bool { return true }
