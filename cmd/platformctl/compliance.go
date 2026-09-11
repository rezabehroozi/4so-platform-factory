package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"platform.4so.io/factory/internal/compliance"
)

func complianceCommand(args []string) {
	if len(args) == 0 || args[0] != "evaluate" {
		usage()
		return
	}
	fs := flag.NewFlagSet("compliance evaluate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("f", "", "Kubernetes object, List, or array encoded as JSON")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || strings.TrimSpace(*path) == "" {
		fatal(fmt.Errorf("compliance evaluate requires -f FILE"))
	}
	data, err := os.ReadFile(*path)
	if err != nil {
		fatal(err)
	}
	result, err := compliance.EvaluateJSON(data)
	if err != nil {
		fatal(err)
	}
	printJSON(result)
}
