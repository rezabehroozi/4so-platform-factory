package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"strings"
	"time"

	"platform.4so.io/factory/internal/remotebootstrap"
)

func installerRemoteCommand(args []string) {
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}
	switch args[0] {
	case "help", "--help", "-h":
		usage()
		return
	case "preflight", "plan":
		installerRemotePrepare(args[0], args[1:])
	case "apply":
		installerRemoteApply(args[1:])
	case "status":
		installerRemoteStatus(args[1:])
	case "verify":
		installerRemoteVerify(args[1:])
	case "rollback":
		installerRemoteRollback(args[1:])
	case "recover":
		installerRemoteRecover(args[1:])
	case "export-access":
		installerRemoteExportAccess(args[1:])
	case "receive-stage":
		installerRemoteReceiveStage(args[1:])
	case "verify-stage":
		installerRemoteVerifyStage(args[1:])
	case "remove-stage":
		installerRemoteRemoveStage(args[1:])
	default:
		usage()
		os.Exit(2)
	}
}

func remoteCommon(fs *flag.FlagSet) (*string, *time.Duration) {
	spec := fs.String("spec", "", "strict JSON remote installer bootstrap specification")
	timeout := fs.Duration("timeout", 5*time.Minute, "remote operation timeout")
	return spec, timeout
}

func installerRemotePrepare(mode string, args []string) {
	fs := flag.NewFlagSet("installer-remote "+mode, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	spec, timeout := remoteCommon(fs)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		usage()
		os.Exit(2)
	}
	if strings.TrimSpace(*spec) == "" || *timeout <= 0 || fs.NArg() != 0 {
		usage()
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	prepared, err := remotebootstrap.Prepare(ctx, *spec, remotebootstrap.Options{})
	if err != nil {
		fatal(err)
	}
	if mode == "preflight" {
		printJSON(prepared.Admission)
		if !prepared.Admission.Ready {
			os.Exit(1)
		}
		return
	}
	printJSON(prepared)
}

func installerRemoteApply(args []string) {
	fs := flag.NewFlagSet("installer-remote apply", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	spec, timeout := remoteCommon(fs)
	confirmation := fs.String("confirmation", "", "must be DEPLOY")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		usage()
		os.Exit(2)
	}
	if strings.TrimSpace(*spec) == "" || *timeout <= 0 || fs.NArg() != 0 {
		usage()
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	result, err := remotebootstrap.Apply(ctx, *spec, *confirmation, remotebootstrap.Options{})
	if err != nil {
		fatal(err)
	}
	printJSON(result)
}

func installerRemoteStatus(args []string) {
	fs := flag.NewFlagSet("installer-remote status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	spec, timeout := remoteCommon(fs)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		usage()
		os.Exit(2)
	}
	if strings.TrimSpace(*spec) == "" || *timeout <= 0 || fs.NArg() != 0 {
		usage()
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	state, err := remotebootstrap.Status(ctx, *spec, remotebootstrap.Options{})
	if err != nil {
		fatal(err)
	}
	printJSON(state)
}
func installerRemoteVerify(args []string) {
	fs := flag.NewFlagSet("installer-remote verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	spec, timeout := remoteCommon(fs)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		usage()
		os.Exit(2)
	}
	if strings.TrimSpace(*spec) == "" || *timeout <= 0 || fs.NArg() != 0 {
		usage()
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	result, err := remotebootstrap.Verify(ctx, *spec, remotebootstrap.Options{})
	if err != nil {
		fatal(err)
	}
	printJSON(result)
}
func installerRemoteRollback(args []string) {
	fs := flag.NewFlagSet("installer-remote rollback", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	spec, timeout := remoteCommon(fs)
	confirmation := fs.String("confirmation", "", "must be ROLLBACK")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		usage()
		os.Exit(2)
	}
	if strings.TrimSpace(*spec) == "" || *timeout <= 0 || fs.NArg() != 0 {
		usage()
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	state, err := remotebootstrap.Rollback(ctx, *spec, *confirmation, remotebootstrap.Options{})
	if err != nil {
		fatal(err)
	}
	printJSON(state)
}
func installerRemoteRecover(args []string) {
	fs := flag.NewFlagSet("installer-remote recover", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	spec, timeout := remoteCommon(fs)
	confirmation := fs.String("confirmation", "", "must be RECOVER")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		usage()
		os.Exit(2)
	}
	if strings.TrimSpace(*spec) == "" || *timeout <= 0 || fs.NArg() != 0 {
		usage()
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	state, err := remotebootstrap.Recover(ctx, *spec, *confirmation, remotebootstrap.Options{})
	if err != nil {
		fatal(err)
	}
	printJSON(state)
}

func installerRemoteExportAccess(args []string) {
	fs := flag.NewFlagSet("installer-remote export-access", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	spec, timeout := remoteCommon(fs)
	output := fs.String("out-token-file", "", "private local file that will receive the remote bootstrap token")
	confirmation := fs.String("confirmation", "", "must be EXPORT")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		usage()
		os.Exit(2)
	}
	if strings.TrimSpace(*spec) == "" || strings.TrimSpace(*output) == "" || *confirmation != "EXPORT" || *timeout <= 0 || fs.NArg() != 0 {
		usage()
		os.Exit(2)
	}
	if _, err := os.Stat(*output); err == nil {
		fatal(errors.New("output token file already exists; refusing to overwrite an access credential"))
	} else if !errors.Is(err, os.ErrNotExist) {
		fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	raw, handoff, err := remotebootstrap.FetchBootstrapToken(ctx, *spec, remotebootstrap.Options{})
	if err != nil {
		fatal(err)
	}
	pending, absolute, err := stagePrivateToken(*output, raw)
	if err != nil {
		fatal(err)
	}
	if err = commitPrivateToken(pending, absolute); err != nil {
		fatal(err)
	}
	printJSON(map[string]any{"exported": true, "tokenFile": absolute, "access": handoff})
}

func installerRemoteReceiveStage(args []string) {
	fs := flag.NewFlagSet("installer-remote receive-stage", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", "", "private remote staging directory")
	digest := fs.String("manifest-digest", "", "expected stage manifest digest")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}
	if *dir == "" || *digest == "" || fs.NArg() != 0 {
		fatal(errors.New("receive-stage requires --dir and --manifest-digest"))
	}
	manifest, err := remotebootstrap.ReceiveStage(*dir, *digest, os.Stdin)
	if err != nil {
		fatal(err)
	}
	printJSON(manifest)
}
func installerRemoteVerifyStage(args []string) {
	fs := flag.NewFlagSet("installer-remote verify-stage", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", "", "private remote staging directory")
	digest := fs.String("manifest-digest", "", "expected stage manifest digest")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}
	if *dir == "" || *digest == "" || fs.NArg() != 0 {
		fatal(errors.New("verify-stage requires --dir and --manifest-digest"))
	}
	manifest, err := remotebootstrap.VerifyStage(*dir, *digest)
	if err != nil {
		fatal(err)
	}
	printJSON(manifest)
}
func installerRemoteRemoveStage(args []string) {
	fs := flag.NewFlagSet("installer-remote remove-stage", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", "", "private remote staging directory")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}
	if *dir == "" || fs.NArg() != 0 {
		fatal(errors.New("remove-stage requires --dir"))
	}
	if err := remotebootstrap.RemoveStage(*dir); err != nil {
		fatal(err)
	}
	printJSON(map[string]any{"removed": true})
}
