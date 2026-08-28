package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"platform.4so.io/factory/internal/hostdeployment"
)

func installerHostCommand(args []string) {
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}
	switch args[0] {
	case "help", "--help", "-h":
		usage()
		return
	case "preflight":
		installerHostPreflight(args[1:])
	case "plan":
		installerHostPlan(args[1:])
	case "apply":
		installerHostApply(args[1:])
	case "verify":
		installerHostVerify(args[1:])
	case "status":
		installerHostStatus(args[1:])
	case "rollback":
		installerHostRollback(args[1:])
	case "recover":
		installerHostRecover(args[1:])
	default:
		usage()
		os.Exit(2)
	}
}

func installerHostPreflight(args []string) {
	fs := flag.NewFlagSet("installer-host preflight", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	spec := fs.String("spec", "", "strict JSON installer host deployment specification")
	root := fs.String("root", "/", "target filesystem root; use / for a live host")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		usage()
		os.Exit(2)
	}
	if strings.TrimSpace(*spec) == "" || fs.NArg() != 0 {
		usage()
		os.Exit(2)
	}
	plan, err := hostdeployment.BuildPlan(*spec, hostdeployment.Options{Root: *root})
	if err != nil {
		fatal(err)
	}
	printJSON(plan.Admission)
	if !plan.Admission.Ready {
		os.Exit(1)
	}
}

func installerHostPlan(args []string) {
	fs := flag.NewFlagSet("installer-host plan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	spec := fs.String("spec", "", "strict JSON installer host deployment specification")
	root := fs.String("root", "/", "target filesystem root; use / for a live host")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		usage()
		os.Exit(2)
	}
	if strings.TrimSpace(*spec) == "" || fs.NArg() != 0 {
		usage()
		os.Exit(2)
	}
	plan, err := hostdeployment.BuildPlan(*spec, hostdeployment.Options{Root: *root})
	if err != nil {
		fatal(err)
	}
	printJSON(plan)
}

func installerHostApply(args []string) {
	fs := flag.NewFlagSet("installer-host apply", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	spec := fs.String("spec", "", "strict JSON installer host deployment specification")
	root := fs.String("root", "/", "target filesystem root; use / for a live host")
	confirmation := fs.String("confirmation", "", "must be DEPLOY")
	timeout := fs.Duration("timeout", 2*time.Minute, "systemd activation timeout")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		usage()
		os.Exit(2)
	}
	if strings.TrimSpace(*spec) == "" || fs.NArg() != 0 || *timeout <= 0 {
		usage()
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	state, err := hostdeployment.Apply(ctx, *spec, *confirmation, hostdeployment.Options{Root: *root})
	if err != nil {
		fatal(err)
	}
	printJSON(state)
}

func installerHostStatus(args []string) {
	fs := flag.NewFlagSet("installer-host status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	statePath := fs.String("state", "", "installer host deployment state file")
	root := fs.String("root", "/", "target filesystem root; used only to resolve the default state path")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		usage()
		os.Exit(2)
	}
	if fs.NArg() != 0 {
		usage()
		os.Exit(2)
	}
	if strings.TrimSpace(*statePath) == "" {
		*statePath = filepath.Join(*root, "var/lib/4so-platform-installer/host-deployment.json")
	}
	state, err := hostdeployment.LoadState(*statePath)
	if err != nil {
		fatal(err)
	}
	printJSON(state)
}

func installerHostVerify(args []string) {
	fs := flag.NewFlagSet("installer-host verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	statePath := fs.String("state", "", "installer host deployment state file")
	root := fs.String("root", "/", "target filesystem root; used only to resolve the default state path")
	timeout := fs.Duration("timeout", 30*time.Second, "systemd verification timeout")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		usage()
		os.Exit(2)
	}
	if fs.NArg() != 0 || *timeout <= 0 {
		usage()
		os.Exit(2)
	}
	if strings.TrimSpace(*statePath) == "" {
		*statePath = filepath.Join(*root, "var/lib/4so-platform-installer/host-deployment.json")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	result, err := hostdeployment.Verify(ctx, *statePath, hostdeployment.Options{})
	if err != nil {
		fatal(err)
	}
	printJSON(result)
}

func installerHostRollback(args []string) {
	fs := flag.NewFlagSet("installer-host rollback", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	statePath := fs.String("state", "", "installer host deployment state file")
	root := fs.String("root", "/", "target filesystem root; used only to resolve the default state path")
	confirmation := fs.String("confirmation", "", "must be ROLLBACK")
	timeout := fs.Duration("timeout", 2*time.Minute, "systemd rollback timeout")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		usage()
		os.Exit(2)
	}
	if fs.NArg() != 0 || *timeout <= 0 {
		usage()
		os.Exit(2)
	}
	if strings.TrimSpace(*statePath) == "" {
		*statePath = filepath.Join(*root, "var/lib/4so-platform-installer/host-deployment.json")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	state, err := hostdeployment.Rollback(ctx, *statePath, *confirmation, hostdeployment.Options{})
	if err != nil {
		fatal(err)
	}
	printJSON(state)
}

func installerHostRecover(args []string) {
	fs := flag.NewFlagSet("installer-host recover", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	statePath := fs.String("state", "", "installer host deployment state file")
	root := fs.String("root", "/", "target filesystem root; used only to resolve the default state path")
	confirmation := fs.String("confirmation", "", "must be RECOVER")
	timeout := fs.Duration("timeout", 2*time.Minute, "systemd recovery timeout")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		usage()
		os.Exit(2)
	}
	if fs.NArg() != 0 || *timeout <= 0 {
		usage()
		os.Exit(2)
	}
	if strings.TrimSpace(*statePath) == "" {
		*statePath = filepath.Join(*root, "var/lib/4so-platform-installer/host-deployment.json")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	state, err := hostdeployment.Recover(ctx, *statePath, *confirmation, hostdeployment.Options{})
	if err != nil {
		fatal(err)
	}
	printJSON(state)
}
