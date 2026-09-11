package externalregistry

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"platform.4so.io/factory/internal/imagebundle"
)

const Authority = "EXTERNAL_REGISTRY_ADMISSION_AUTHORITY_V1"

var credentialRefPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type Request struct {
	RegistryURL    string `json:"registryUrl"`
	ImageReference string `json:"imageReference"`
	Direction      string `json:"direction"`
	CredentialRef  string `json:"credentialRef,omitempty"`
}

type Result struct {
	Authority             string `json:"authority"`
	Admitted              bool   `json:"admitted"`
	Direction             string `json:"direction"`
	RegistryURL           string `json:"registryUrl"`
	RegistryHost          string `json:"registryHost"`
	Repository            string `json:"repository"`
	Digest                string `json:"digest"`
	CredentialRef         string `json:"credentialRef,omitempty"`
	RawCredentialsAllowed bool   `json:"rawCredentialsAllowed"`
	MutableTagsAllowed    bool   `json:"mutableTagsAllowed"`
	ManagedRegistrySoT    string `json:"managedRegistrySoT"`
}

func Admit(in Request) (Result, error) {
	u, err := url.Parse(strings.TrimSpace(in.RegistryURL))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return Result{}, fmt.Errorf("external registry URL must be absolute HTTPS")
	}
	if u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return Result{}, fmt.Errorf("external registry URL must contain only scheme and host without credentials, path, query or fragment")
	}
	registry, repository, digest, err := imagebundle.ParseDigestReference(strings.TrimSpace(in.ImageReference))
	if err != nil {
		return Result{}, err
	}
	if !strings.EqualFold(registry, u.Host) {
		return Result{}, fmt.Errorf("image reference registry must match registryUrl host")
	}
	direction := strings.ToUpper(strings.TrimSpace(in.Direction))
	switch direction {
	case "IMPORT", "EXPORT", "MIRROR":
	default:
		return Result{}, fmt.Errorf("direction must be IMPORT, EXPORT or MIRROR")
	}
	credentialRef := strings.TrimSpace(in.CredentialRef)
	if credentialRef != "" && !credentialRefPattern.MatchString(credentialRef) {
		return Result{}, fmt.Errorf("credentialRef must be an opaque server-side identifier using only letters, digits, dot, underscore or hyphen")
	}
	return Result{
		Authority:             Authority,
		Admitted:              true,
		Direction:             direction,
		RegistryURL:           "https://" + u.Host,
		RegistryHost:          u.Host,
		Repository:            repository,
		Digest:                digest,
		CredentialRef:         credentialRef,
		RawCredentialsAllowed: false,
		MutableTagsAllowed:    false,
		ManagedRegistrySoT:    "zot",
	}, nil
}
