package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"platform.4so.io/factory/internal/imagebundle"
)

func imageBundleUsage(command string) {
	switch command {
	case "assemble":
		fmt.Fprintln(os.Stderr, "usage: platformctl image-bundle assemble --oci-layout DIR --reference REGISTRY/REPOSITORY@sha256:DIGEST --out IMAGE-BUNDLE.zip")
	case "verify":
		fmt.Fprintln(os.Stderr, "usage: platformctl image-bundle verify -f IMAGE-BUNDLE.zip")
	case "push":
		fmt.Fprintln(os.Stderr, "usage: platformctl image-bundle push -f IMAGE-BUNDLE.zip --registry-url http(s)://REGISTRY --confirmation MIRROR")
	default:
		usage()
	}
}

func imageBundleCommand(args []string) {
	if len(args) == 0 {
		usage()
		return
	}
	if len(args) > 1 && (args[1] == "--help" || args[1] == "-h") {
		imageBundleUsage(args[0])
		return
	}
	switch args[0] {
	case "assemble":
		fs := flag.NewFlagSet("image-bundle assemble", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		layout := fs.String("oci-layout", "", "OCI image-layout directory")
		reference := fs.String("reference", "", "exact source registry/repository@sha256:digest")
		out := fs.String("out", "", "output deterministic image bundle zip")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || strings.TrimSpace(*layout) == "" || strings.TrimSpace(*reference) == "" || strings.TrimSpace(*out) == "" {
			fatal(fmt.Errorf("image-bundle assemble requires --oci-layout DIR --reference REGISTRY/REPOSITORY@sha256:DIGEST --out FILE"))
		}
		raw, verified, err := imagebundle.Assemble(*layout, *reference)
		if err != nil {
			fatal(err)
		}
		if err = os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
			fatal(err)
		}
		if _, err = os.Lstat(*out); err == nil {
			fatal(fmt.Errorf("refusing to overwrite existing image bundle %s", *out))
		} else if !os.IsNotExist(err) {
			fatal(err)
		}
		if err = os.WriteFile(*out, raw, 0o644); err != nil {
			fatal(err)
		}
		printJSON(map[string]any{
			"assembled": true, "out": *out, "bundleDigest": verified.BundleDigest,
			"sourceReference": verified.Manifest.SourceReference, "rootDigest": verified.Manifest.RootDigest,
			"rootMediaType": verified.Manifest.RootMediaType, "mirrorRepository": verified.Manifest.MirrorRepository,
			"blobCount": verified.Manifest.BlobCount, "manifestCount": verified.Manifest.ManifestCount,
			"totalBytes": verified.Manifest.TotalBytes, "networkFetchRequired": false,
		})
	case "verify":
		fs := flag.NewFlagSet("image-bundle verify", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		file := fs.String("f", "", "OCI image mirror bundle")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || strings.TrimSpace(*file) == "" {
			fatal(fmt.Errorf("image-bundle verify requires -f IMAGE-BUNDLE.zip"))
		}
		raw, err := os.ReadFile(*file)
		if err != nil {
			fatal(err)
		}
		verified, err := imagebundle.Verify(raw)
		if err != nil {
			fatal(err)
		}
		printJSON(map[string]any{
			"valid": true, "bundleDigest": verified.BundleDigest,
			"sourceReference": verified.Manifest.SourceReference, "rootDigest": verified.Manifest.RootDigest,
			"rootMediaType": verified.Manifest.RootMediaType, "mirrorRepository": verified.Manifest.MirrorRepository,
			"blobCount": verified.Manifest.BlobCount, "manifestCount": verified.Manifest.ManifestCount,
			"totalBytes": verified.Manifest.TotalBytes, "offlineReady": true, "networkFetchRequired": false,
		})
	case "push":
		fs := flag.NewFlagSet("image-bundle push", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		file := fs.String("f", "", "OCI image mirror bundle")
		registryURL := fs.String("registry-url", "", "managed Distribution-compatible registry base URL")
		confirmation := fs.String("confirmation", "", "must be MIRROR")
		timeout := fs.Duration("timeout", 2*time.Minute, "registry push timeout")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || strings.TrimSpace(*file) == "" || strings.TrimSpace(*registryURL) == "" || *confirmation != "MIRROR" || *timeout <= 0 {
			fatal(fmt.Errorf("image-bundle push requires -f IMAGE-BUNDLE.zip --registry-url URL --confirmation MIRROR"))
		}
		raw, err := os.ReadFile(*file)
		if err != nil {
			fatal(err)
		}
		verified, err := imagebundle.Verify(raw)
		if err != nil {
			fatal(err)
		}
		client, err := imagebundle.NewRegistryClient(*registryURL)
		if err != nil {
			fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		defer cancel()
		result, err := client.Push(ctx, verified)
		if err != nil {
			fatal(err)
		}
		printJSON(map[string]any{
			"mirrored": result.Verified, "bundleDigest": verified.BundleDigest,
			"sourceReference": result.SourceReference, "mirrorReference": result.MirrorReference,
			"repository": result.Repository, "digest": result.Digest,
			"uploadedBlobs": result.UploadedBlobs, "uploadedManifests": result.UploadedManifests,
			"registryVerified": result.Verified, "networkFetchRequired": false,
		})
	default:
		usage()
		fmt.Fprintln(os.Stderr, "unknown image-bundle command:", args[0])
	}
}
