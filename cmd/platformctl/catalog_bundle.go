package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"platform.4so.io/factory/internal/catalogbundle"
)

func catalogBundleCommand(args []string) {
	if len(args) == 0 {
		usage()
		return
	}
	if len(args) > 1 && (args[1] == "--help" || args[1] == "-h") {
		switch args[0] {
		case "assemble":
			fmt.Fprintln(os.Stderr, "usage: platformctl catalog-bundle assemble --component FILE --artifact FILE --render-manifest FILE --image-inventory FILE --licenses FILE --sbom FILE [--render-generation FILE] --version VERSION [--source-type helm-chart|external-tagged-source-set] --source-url URL --source-revision REV --upstream-artifact-name NAME --artifact-digest sha256:HEX --bundle-key COMPONENT/VERSION --out BUNDLE.zip")
		case "verify":
			fmt.Fprintln(os.Stderr, "usage: platformctl catalog-bundle verify -f BUNDLE.zip")
		case "install":
			fmt.Fprintln(os.Stderr, "usage: platformctl catalog-bundle install -f BUNDLE.zip --repo-root DIR --confirmation IMPORT")
		default:
			usage()
		}
		return
	}
	switch args[0] {
	case "assemble":
		fs := flag.NewFlagSet("catalog-bundle assemble", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		component := fs.String("component", "", "base unresolved component JSON")
		artifact := fs.String("artifact", "", "offline upstream artifact bytes")
		renderManifest := fs.String("render-manifest", "", "normalized JSON resource list")
		images := fs.String("image-inventory", "", "digest-pinned image inventory JSON")
		licenses := fs.String("licenses", "", "license manifest JSON")
		sbom := fs.String("sbom", "", "SPDX JSON SBOM")
		renderGeneration := fs.String("render-generation", "", "Helm render generation evidence JSON; required for helm-chart sources")
		version := fs.String("version", "", "exact upstream version")
		sourceType := fs.String("source-type", "helm-chart", "source type")
		sourceURL := fs.String("source-url", "", "upstream artifact source URL")
		sourceRevision := fs.String("source-revision", "", "upstream tag/commit/revision")
		upstreamArtifact := fs.String("upstream-artifact-name", "", "upstream artifact filename")
		artifactDigest := fs.String("artifact-digest", "", "independently pinned upstream artifact sha256 digest")
		bundleKey := fs.String("bundle-key", "", "catalog runtime bundle key component/version")
		out := fs.String("out", "", "output bundle zip")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
			fatal(err)
		}
		required := map[string]string{"component": *component, "artifact": *artifact, "render-manifest": *renderManifest, "image-inventory": *images, "licenses": *licenses, "sbom": *sbom, "version": *version, "source-url": *sourceURL, "source-revision": *sourceRevision, "upstream-artifact-name": *upstreamArtifact, "artifact-digest": *artifactDigest, "bundle-key": *bundleKey, "out": *out}
		for name, value := range required {
			if strings.TrimSpace(value) == "" {
				fatal(fmt.Errorf("catalog-bundle assemble requires --%s", name))
			}
		}
		read := func(path string) []byte {
			b, err := os.ReadFile(path)
			if err != nil {
				fatal(err)
			}
			return b
		}
		var generation []byte
		if strings.TrimSpace(*renderGeneration) != "" {
			generation = read(*renderGeneration)
		}
		raw, verified, err := catalogbundle.Assemble(catalogbundle.AssembleInput{BaseComponent: read(*component), Artifact: read(*artifact), RenderManifest: read(*renderManifest), ImageInventory: read(*images), Licenses: read(*licenses), SBOM: read(*sbom), RenderGeneration: generation, Version: *version, SourceType: *sourceType, SourceURL: *sourceURL, SourceRevision: *sourceRevision, UpstreamArtifact: *upstreamArtifact, ExpectedArtifactDigest: *artifactDigest, BundleKey: *bundleKey})
		if err != nil {
			fatal(err)
		}
		if err = os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
			fatal(err)
		}
		if err = os.WriteFile(*out, raw, 0o644); err != nil {
			fatal(err)
		}
		printJSON(map[string]any{"assembled": true, "out": *out, "component": verified.Manifest.Component, "version": verified.Manifest.Version, "bundleDigest": verified.BundleDigest, "upstreamArtifactDigest": verified.Manifest.Upstream.ArtifactDigest, "resourceCount": verified.ResourceCount, "imageCount": verified.ImageCount, "offlineReady": true, "networkFetchRequired": false})
	case "verify":
		fs := flag.NewFlagSet("catalog-bundle verify", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		file := fs.String("f", "", "offline external catalog bundle zip")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || strings.TrimSpace(*file) == "" {
			fatal(fmt.Errorf("catalog-bundle verify requires -f BUNDLE.zip"))
		}
		verified, err := catalogbundle.VerifyFile(*file)
		if err != nil {
			fatal(err)
		}
		printJSON(map[string]any{
			"valid": true, "component": verified.Manifest.Component, "version": verified.Manifest.Version,
			"sourceType": verified.Manifest.SourceType, "bundleKey": verified.Manifest.BundleKey,
			"bundleDigest": verified.BundleDigest, "upstreamUrl": verified.Manifest.Upstream.URL,
			"upstreamRevision": verified.Manifest.Upstream.Revision, "upstreamArtifact": verified.Manifest.Upstream.Artifact,
			"upstreamArtifactDigest": verified.Manifest.Upstream.ArtifactDigest,
			"resourceCount":          verified.ResourceCount, "imageCount": verified.ImageCount, "licenseCount": verified.LicenseCount,
			"offlineReady": verified.OfflineReady, "networkFetchRequired": false,
		})
	case "install":
		fs := flag.NewFlagSet("catalog-bundle install", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		file := fs.String("f", "", "offline external catalog bundle zip")
		repo := fs.String("repo-root", ".", "Platform Factory source root")
		confirmation := fs.String("confirmation", "", "must be IMPORT")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || strings.TrimSpace(*file) == "" || *confirmation != "IMPORT" {
			fatal(fmt.Errorf("catalog-bundle install requires -f BUNDLE.zip --repo-root DIR --confirmation IMPORT"))
		}
		verified, err := catalogbundle.VerifyFile(*file)
		if err != nil {
			fatal(err)
		}
		if err = catalogbundle.Install(verified, *repo); err != nil {
			fatal(err)
		}
		root, _ := filepath.Abs(*repo)
		printJSON(map[string]any{
			"installed": true, "component": verified.Manifest.Component, "version": verified.Manifest.Version,
			"bundleDigest": verified.BundleDigest, "runtimeBundleDir": filepath.Join(root, "catalog", "runtime", filepath.FromSlash(verified.Manifest.BundleKey)),
			"componentContract":    filepath.Join(root, "catalog", "components", verified.Manifest.Component+".json"),
			"networkFetchRequired": false, "next": "rebuild the release so the verified bundle is embedded into catalog/runtime",
		})
	default:
		usage()
		if len(args) > 0 {
			fmt.Fprintln(os.Stderr, "unknown catalog-bundle command:", args[0])
		}
	}
}
