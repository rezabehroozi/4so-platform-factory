package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"platform.4so.io/factory/internal/manifestimages"
	"platform.4so.io/factory/internal/ociarchive"
	"platform.4so.io/factory/internal/registryacquire"
	"platform.4so.io/factory/internal/releaseartifact"
)

type sourceImageFlags []string

func (s *sourceImageFlags) String() string { return strings.Join(*s, ",") }
func (s *sourceImageFlags) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func workloadOCIUsage() {
	fmt.Fprintln(os.Stderr, "usage: platformctl workload-oci assemble --source REGISTRY/REPO@sha256:DIGEST=OCI_LAYOUT_DIR [--source ...] --out workloads.oci.tar")
	fmt.Fprintln(os.Stderr, "       platformctl workload-oci certify-product --release EXACT_RELEASE.zip --role platform-api|platform-agent|platform-probe --source REGISTRY/REPO@sha256:DIGEST=OCI_LAYOUT_DIR")
	fmt.Fprintln(os.Stderr, "       platformctl workload-oci inspect-manifest --manifest SOURCE.yaml")
	fmt.Fprintln(os.Stderr, "       platformctl workload-oci resolve-manifest --manifest SOURCE.yaml --resolution SOURCE_REF=REGISTRY/REPO@sha256:DIGEST [--resolution ...] --out-manifest FILE --out-lock FILE")
	fmt.Fprintln(os.Stderr, "       platformctl workload-oci acquire-external --release EXACT_RELEASE.zip --plan management-workload-image-build-plan.json --role postgresql|forgejo|zot|keycloak --out-layout DIR --out-lock FILE")
	fmt.Fprintln(os.Stderr, "       platformctl workload-oci verify-external --release EXACT_RELEASE.zip --plan management-workload-image-build-plan.json --role postgresql|forgejo|zot|keycloak --layout DIR --lock FILE")
}

func parseWorkloadOCISource(raw string) (ociarchive.SourceImage, error) {
	at := strings.LastIndex(raw, "@sha256:")
	if at <= 0 {
		return ociarchive.SourceImage{}, fmt.Errorf("workload-oci source %q is missing an exact digest reference", raw)
	}
	separator := strings.Index(raw[at+len("@sha256:"):], "=")
	if separator < 0 {
		return ociarchive.SourceImage{}, fmt.Errorf("workload-oci source %q must end with =OCI_LAYOUT_DIR", raw)
	}
	separator += at + len("@sha256:")
	reference := raw[:separator]
	layout := raw[separator+1:]
	if strings.TrimSpace(reference) != reference || strings.TrimSpace(layout) != layout || layout == "" {
		return ociarchive.SourceImage{}, fmt.Errorf("workload-oci source %q is not canonical", raw)
	}
	return ociarchive.SourceImage{Reference: reference, LayoutDir: layout}, nil
}

type manifestResolutionFlags []string

func (m *manifestResolutionFlags) String() string { return strings.Join(*m, ",") }
func (m *manifestResolutionFlags) Set(value string) error {
	*m = append(*m, value)
	return nil
}

func readManifestInput(path string) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("manifest path is required")
	}
	before, err := os.Lstat(path)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > 16*1024*1024 {
		return nil, fmt.Errorf("manifest must be a non-empty regular non-symlink file no larger than 16 MiB")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open manifest safely: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("open manifest safely")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, fmt.Errorf("manifest changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 16*1024*1024+1))
	if err != nil || len(raw) != int(opened.Size()) {
		return nil, fmt.Errorf("read manifest safely")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(opened, after) || after.Size() != int64(len(raw)) {
		return nil, fmt.Errorf("manifest changed while reading")
	}
	return raw, nil
}

func workloadOCIInspectManifest(args []string) {
	fs := flag.NewFlagSet("workload-oci inspect-manifest", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	manifestPath := fs.String("manifest", "", "exact upstream Kubernetes manifest")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || strings.TrimSpace(*manifestPath) == "" {
		fatal(fmt.Errorf("workload-oci inspect-manifest requires --manifest SOURCE.yaml"))
	}
	raw, err := readManifestInput(*manifestPath)
	if err != nil {
		fatal(err)
	}
	refs, err := manifestimages.Extract(raw)
	if err != nil {
		fatal(err)
	}
	mutable := make([]string, 0, len(refs))
	for _, ref := range refs {
		if !strings.Contains(ref, "@sha256:") {
			mutable = append(mutable, ref)
		}
	}
	printJSON(map[string]any{"authority": manifestimages.ResolutionAuthority, "manifest": *manifestPath, "images": refs, "imageCount": len(refs), "resolutionRequired": mutable, "resolutionRequiredCount": len(mutable)})
}

func workloadOCIResolveManifest(args []string) {
	fs := flag.NewFlagSet("workload-oci resolve-manifest", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	manifestPath := fs.String("manifest", "", "exact upstream Kubernetes manifest")
	outManifest := fs.String("out-manifest", "", "digest-pinned runtime manifest output")
	outLock := fs.String("out-lock", "", "manifest image resolution lock output")
	var rawResolutions manifestResolutionFlags
	fs.Var(&rawResolutions, "resolution", "SOURCE_REF=REGISTRY/REPO@sha256:DIGEST; repeat for each mutable image")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || strings.TrimSpace(*manifestPath) == "" || strings.TrimSpace(*outManifest) == "" || strings.TrimSpace(*outLock) == "" {
		fatal(fmt.Errorf("workload-oci resolve-manifest requires --manifest SOURCE.yaml --resolution SOURCE_REF=REGISTRY/REPO@sha256:DIGEST [--resolution ...] --out-manifest FILE --out-lock FILE"))
	}
	mappings := map[string]string{}
	for _, raw := range rawResolutions {
		parts := strings.SplitN(raw, "=", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) != parts[0] || strings.TrimSpace(parts[1]) != parts[1] || parts[0] == "" || parts[1] == "" {
			fatal(fmt.Errorf("manifest resolution %q must be SOURCE_REF=REGISTRY/REPO@sha256:DIGEST", raw))
		}
		if _, exists := mappings[parts[0]]; exists {
			fatal(fmt.Errorf("duplicate manifest resolution for %q", parts[0]))
		}
		mappings[parts[0]] = parts[1]
	}
	raw, err := readManifestInput(*manifestPath)
	if err != nil {
		fatal(err)
	}
	result, err := manifestimages.WriteResolved(raw, mappings, *outManifest, *outLock)
	if err != nil {
		fatal(err)
	}
	printJSON(map[string]any{"resolved": true, "authority": result.Authority, "sourceManifestSha256": result.SourceManifestSHA256, "resolvedManifestSha256": result.ResolvedManifestSHA256, "imageCount": len(result.Images), "outManifest": *outManifest, "outLock": *outLock, "images": result.Images})
}

func workloadOCIAcquireExternal(args []string) {
	fs := flag.NewFlagSet("workload-oci acquire-external", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	releasePath := fs.String("release", "", "exact release ZIP carrying the image version-selection authority")
	planPath := fs.String("plan", "", "management workload image build plan extracted from the exact release")
	role := fs.String("role", "", "external image role: postgresql, forgejo, zot or keycloak")
	outLayout := fs.String("out-layout", "", "new local OCI layout output directory")
	outLock := fs.String("out-lock", "", "new external image acquisition lock output")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || strings.TrimSpace(*releasePath) == "" || strings.TrimSpace(*planPath) == "" || strings.TrimSpace(*role) == "" || strings.TrimSpace(*outLayout) == "" || strings.TrimSpace(*outLock) == "" {
		fatal(fmt.Errorf("workload-oci acquire-external requires --release EXACT_RELEASE.zip --plan FILE --role ROLE --out-layout DIR --out-lock FILE"))
	}
	release, err := releaseartifact.Inspect(*releasePath, version)
	if err != nil {
		fatal(fmt.Errorf("inspect exact release: %w", err))
	}
	platformctlDigest := bindRunningPlatformctlToExactRelease(release)
	planRaw, err := readManifestInput(*planPath)
	if err != nil {
		fatal(fmt.Errorf("read management workload image plan safely: %w", err))
	}
	planSum := sha256.Sum256(planRaw)
	planDigest := "sha256:" + hex.EncodeToString(planSum[:])
	expectedPlanDigest, err := release.FileDigest("lab/management-workload-image-build-plan.json")
	if err != nil {
		fatal(err)
	}
	if planDigest != expectedPlanDigest {
		fatal(fmt.Errorf("management workload image plan digest %s does not match exact release %s", planDigest, expectedPlanDigest))
	}
	spec, err := registryacquire.ParsePlanExternal(planRaw, strings.TrimSpace(*role), release.Version)
	if err != nil {
		fatal(err)
	}
	spec.ReleaseArtifactDigest = release.Digest
	spec.PlanDigest = planDigest
	result, err := registryacquire.NewPublicClient().Acquire(context.Background(), spec, *outLayout, *outLock)
	if err != nil {
		fatal(err)
	}
	printJSON(map[string]any{
		"acquired":                true,
		"authority":               registryacquire.Authority,
		"platformctlBinaryDigest": platformctlDigest,
		"releaseArtifactDigest":   release.Digest,
		"planDigest":              planDigest,
		"outLayout":               *outLayout,
		"outLock":                 *outLock,
		"result":                  result,
	})
}

func workloadOCIVerifyExternal(args []string) {
	fs := flag.NewFlagSet("workload-oci verify-external", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	releasePath := fs.String("release", "", "exact release ZIP carrying the image version-selection authority")
	planPath := fs.String("plan", "", "management workload image build plan extracted from the exact release")
	role := fs.String("role", "", "external image role: postgresql, forgejo, zot or keycloak")
	layout := fs.String("layout", "", "transferred local OCI layout directory")
	lockPath := fs.String("lock", "", "transferred external image acquisition lock")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || strings.TrimSpace(*releasePath) == "" || strings.TrimSpace(*planPath) == "" || strings.TrimSpace(*role) == "" || strings.TrimSpace(*layout) == "" || strings.TrimSpace(*lockPath) == "" {
		fatal(fmt.Errorf("workload-oci verify-external requires --release EXACT_RELEASE.zip --plan FILE --role ROLE --layout DIR --lock FILE"))
	}
	release, err := releaseartifact.Inspect(*releasePath, version)
	if err != nil {
		fatal(fmt.Errorf("inspect exact release: %w", err))
	}
	platformctlDigest := bindRunningPlatformctlToExactRelease(release)
	planRaw, err := readManifestInput(*planPath)
	if err != nil {
		fatal(fmt.Errorf("read management workload image plan safely: %w", err))
	}
	planSum := sha256.Sum256(planRaw)
	planDigest := "sha256:" + hex.EncodeToString(planSum[:])
	expectedPlanDigest, err := release.FileDigest("lab/management-workload-image-build-plan.json")
	if err != nil {
		fatal(err)
	}
	if planDigest != expectedPlanDigest {
		fatal(fmt.Errorf("management workload image plan digest %s does not match exact release %s", planDigest, expectedPlanDigest))
	}
	spec, err := registryacquire.ParsePlanExternal(planRaw, strings.TrimSpace(*role), release.Version)
	if err != nil {
		fatal(err)
	}
	spec.ReleaseArtifactDigest = release.Digest
	spec.PlanDigest = planDigest
	result, err := registryacquire.VerifyOffline(spec, *layout, *lockPath)
	if err != nil {
		fatal(err)
	}
	printJSON(map[string]any{
		"verified":                true,
		"authority":               registryacquire.Authority,
		"offlineVerification":     true,
		"platformctlBinaryDigest": platformctlDigest,
		"releaseArtifactDigest":   release.Digest,
		"planDigest":              planDigest,
		"role":                    result.Role,
		"exactReference":          result.ExactReference,
		"tagRootDigest":           result.TagRootDigest,
		"manifestDigest":          result.ManifestDigest,
		"reachableBytes":          result.ReachableBytes,
	})
}

func productImageSpec(role string, release releaseartifact.Inspection) (ociarchive.ProductImageSpec, error) {
	var repository, binaryPath, releaseMember string
	var entrypoint []string
	requireCA := false
	expectedLinkage := ""
	var requiredNeeded []string
	switch role {
	case "platform-api":
		expectedLinkage = "dynamic"
		requiredNeeded = []string{"libc.so.6", "libpq.so.5"}
		repository, binaryPath, releaseMember, entrypoint = "platform.4so.local/management/platform-api", "/platform-api", releaseartifact.PlatformAPIBinaryPath, []string{"/platform-api"}
	case "platform-agent":
		expectedLinkage = "static"
		repository, binaryPath, releaseMember, entrypoint = "platform.4so.local/management/platform-agent", "/platform-agent", releaseartifact.PlatformAgentBinaryPath, []string{"/platform-agent"}
		requireCA = true
	case "platform-probe":
		expectedLinkage = "static"
		repository, binaryPath, releaseMember, entrypoint = "platform.4so.local/management/platform-probe", "/platform-probe", releaseartifact.PlatformProbeBinaryPath, []string{"/platform-probe"}
	default:
		return ociarchive.ProductImageSpec{}, fmt.Errorf("unsupported product image role %q", role)
	}
	binaryDigest, err := release.FileDigest(releaseMember)
	if err != nil {
		return ociarchive.ProductImageSpec{}, err
	}
	return ociarchive.ProductImageSpec{
		Role: role, Repository: repository, BinaryPath: binaryPath, ExpectedBinaryDigest: binaryDigest,
		ExpectedUser: "65532:65532", ExpectedEntrypoint: entrypoint, ExpectedReleaseDigest: release.Digest, RequireCABundle: requireCA, ExpectedLinkage: expectedLinkage, RequiredNeeded: requiredNeeded,
	}, nil
}

func workloadOCICertifyProduct(args []string) {
	fs := flag.NewFlagSet("workload-oci certify-product", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	releasePath := fs.String("release", "", "exact release ZIP containing the product binary authority")
	role := fs.String("role", "", "product image role: platform-api, platform-agent or platform-probe")
	rawSource := fs.String("source", "", "exact image reference followed by = and its local OCI layout directory")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || strings.TrimSpace(*releasePath) == "" || strings.TrimSpace(*role) == "" || strings.TrimSpace(*rawSource) == "" {
		fatal(fmt.Errorf("workload-oci certify-product requires --release EXACT_RELEASE.zip --role ROLE --source REGISTRY/REPO@sha256:DIGEST=OCI_LAYOUT_DIR"))
	}
	release, err := releaseartifact.Inspect(*releasePath, version)
	if err != nil {
		fatal(fmt.Errorf("inspect exact release: %w", err))
	}
	platformctlDigest := bindRunningPlatformctlToExactRelease(release)
	source, err := parseWorkloadOCISource(*rawSource)
	if err != nil {
		fatal(err)
	}
	spec, err := productImageSpec(strings.TrimSpace(*role), release)
	if err != nil {
		fatal(err)
	}
	result, err := ociarchive.CertifyProductImage(source, spec)
	if err != nil {
		fatal(err)
	}
	printJSON(map[string]any{"certified": true, "platformctlBinaryDigest": platformctlDigest, "releaseArtifactDigest": release.Digest, "result": result})
}

func workloadOCICommand(args []string) {
	if len(args) == 0 {
		workloadOCIUsage()
		return
	}
	if args[0] == "acquire-external" {
		workloadOCIAcquireExternal(args[1:])
		return
	}
	if args[0] == "verify-external" {
		workloadOCIVerifyExternal(args[1:])
		return
	}
	if args[0] == "certify-product" {
		workloadOCICertifyProduct(args[1:])
		return
	}
	if args[0] == "inspect-manifest" {
		workloadOCIInspectManifest(args[1:])
		return
	}
	if args[0] == "resolve-manifest" {
		workloadOCIResolveManifest(args[1:])
		return
	}
	if args[0] != "assemble" {
		workloadOCIUsage()
		return
	}
	fs := flag.NewFlagSet("workload-oci assemble", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var rawSources sourceImageFlags
	fs.Var(&rawSources, "source", "exact image reference followed by = and its local OCI layout directory; repeat per image")
	out := fs.String("out", "", "output deterministic management workload OCI archive")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || len(rawSources) == 0 || strings.TrimSpace(*out) == "" {
		fatal(fmt.Errorf("workload-oci assemble requires one or more --source REGISTRY/REPO@sha256:DIGEST=OCI_LAYOUT_DIR and --out FILE"))
	}
	sources := make([]ociarchive.SourceImage, 0, len(rawSources))
	for _, raw := range rawSources {
		source, err := parseWorkloadOCISource(raw)
		if err != nil {
			fatal(err)
		}
		sources = append(sources, source)
	}
	result, err := ociarchive.AssembleToFile(sources, *out)
	if err != nil {
		fatal(err)
	}
	printJSON(map[string]any{
		"assembled": true, "authority": result.Authority, "out": *out,
		"archiveSha256": result.ArchiveSHA256, "archiveBytes": result.ArchiveBytes,
		"imageCount": result.ImageCount, "blobCount": result.BlobCount,
		"inventoryAuthority":            result.Inventory.Authority,
		"importAddressabilityAuthority": result.Inventory.ImportAddressabilityAuthority,
		"images":                        result.Inventory.Images,
	})
}
