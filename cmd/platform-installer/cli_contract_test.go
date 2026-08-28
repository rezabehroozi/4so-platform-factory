package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestInstallerCLIHelpAndVersionAreNonDaemonCommands(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"-h"}, {"help"}, {"--version"}, {"version"}} {
		var output bytes.Buffer
		run, err := handleCommandLine(args, &output)
		if err != nil {
			t.Fatalf("args=%v err=%v", args, err)
		}
		if run {
			t.Fatalf("args=%v unexpectedly entered daemon mode", args)
		}
		if strings.TrimSpace(output.String()) == "" {
			t.Fatalf("args=%v produced no CLI output", args)
		}
	}
}

func TestInstallerCLIUnknownArgumentsFailClosedBeforeDaemonMode(t *testing.T) {
	for _, args := range [][]string{{"--typo"}, {"serve"}, {"--help", "extra"}} {
		var output bytes.Buffer
		run, err := handleCommandLine(args, &output)
		if err == nil {
			t.Fatalf("args=%v unexpectedly accepted", args)
		}
		if run {
			t.Fatalf("args=%v unexpectedly entered daemon mode", args)
		}
	}
}

func TestInstallerCLINoArgumentsStartsDaemonMode(t *testing.T) {
	var output bytes.Buffer
	run, err := handleCommandLine(nil, &output)
	if err != nil || !run {
		t.Fatalf("run=%v err=%v", run, err)
	}
	if output.Len() != 0 {
		t.Fatalf("daemon mode emitted unexpected CLI output %q", output.String())
	}
}
