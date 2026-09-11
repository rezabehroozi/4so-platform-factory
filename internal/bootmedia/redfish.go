package bootmedia

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

const RedfishProviderAuthority = "REDFISH_BOOT_MEDIA_PROVIDER_V1"

type Credentials struct {
	Username string
	Password string
}

type CredentialScope struct {
	OrganizationID string
	ProjectID      string
	MachineID      string
	Endpoint       string
	Reference      string
}

type CredentialResolver interface {
	ResolveBootMediaCredential(context.Context, CredentialScope) (Credentials, error)
}

type RedfishProvider struct {
	Client   *http.Client
	Resolver CredentialResolver
	Context  context.Context
}

func (p *RedfishProvider) client() (*http.Client, error) {
	if p.Client != nil {
		if transport, ok := p.Client.Transport.(*http.Transport); ok && transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify {
			return nil, errors.New("redfish TLS verification cannot be disabled")
		}
		return p.Client, nil
	}
	return &http.Client{Timeout: 20 * time.Second}, nil
}

func (p *RedfishProvider) ctx() context.Context {
	if p.Context != nil {
		return p.Context
	}
	return context.Background()
}

func (p *RedfishProvider) credentialsContext(ctx context.Context, req Request) (Credentials, error) {
	if p.Resolver == nil {
		return Credentials{}, errors.New("redfish credential resolver is required")
	}
	c, err := p.Resolver.ResolveBootMediaCredential(ctx, CredentialScope{OrganizationID: req.OrganizationID, ProjectID: req.ProjectID, MachineID: req.MachineID, Endpoint: req.Endpoint, Reference: req.CredentialRef})
	if err != nil {
		return Credentials{}, fmt.Errorf("resolve redfish credential: %w", err)
	}
	if strings.TrimSpace(c.Username) == "" || c.Password == "" {
		return Credentials{}, errors.New("resolved redfish credential is incomplete")
	}
	return c, nil
}

func redfishURL(baseURL, resource string) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil {
		return "", errors.New("invalid redfish https endpoint")
	}
	if !strings.HasPrefix(resource, "/redfish/v1/") || strings.ContainsAny(resource, "?#%\r\n") || path.Clean(resource) != resource {
		return "", errors.New("invalid redfish resource path")
	}
	base.Path = resource
	base.RawPath = ""
	base.RawQuery = ""
	base.Fragment = ""
	return base.String(), nil
}

func (p *RedfishProvider) requestContext(ctx context.Context, req Request, method, resource string, body any, out any) error {
	if err := ValidateRequest(req); err != nil {
		return err
	}
	target, err := redfishURL(req.Endpoint, resource)
	if err != nil {
		return err
	}
	var r io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(encoded)
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, target, r)
	if err != nil {
		return err
	}
	creds, err := p.credentialsContext(ctx, req)
	if err != nil {
		return err
	}
	httpReq.SetBasicAuth(creds.Username, creds.Password)
	httpReq.Header.Set("Accept", "application/json")
	if body != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	client, err := p.client()
	if err != nil {
		return err
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("redfish request failed: %w", err)
	}
	defer resp.Body.Close()
	limited, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("redfish %s %s returned %d", method, resource, resp.StatusCode)
	}
	if out != nil && len(bytes.TrimSpace(limited)) != 0 {
		if err := json.Unmarshal(limited, out); err != nil {
			return fmt.Errorf("decode redfish response: %w", err)
		}
	}
	return nil
}

type redfishVirtualMedia struct {
	Image    string `json:"Image"`
	Inserted bool   `json:"Inserted"`
}

type redfishSystem struct {
	PowerState string `json:"PowerState"`
	Boot       struct {
		Enabled string `json:"BootSourceOverrideEnabled"`
		Target  string `json:"BootSourceOverrideTarget"`
	} `json:"Boot"`
}

func (p *RedfishProvider) request(req Request, method, resource string, body any, out any) error {
	return p.requestContext(p.ctx(), req, method, resource, body, out)
}

func (p *RedfishProvider) AttachContext(ctx context.Context, req Request) error {
	var current redfishVirtualMedia
	if err := p.requestContext(ctx, req, http.MethodGet, req.VirtualMediaResource, nil, &current); err != nil {
		return err
	}
	if current.Inserted {
		if current.Image == req.MediaURL {
			return nil
		}
		return errors.New("redfish virtual media already contains a different image")
	}
	action := strings.TrimSuffix(req.VirtualMediaResource, "/") + "/Actions/VirtualMedia.InsertMedia"
	return p.requestContext(ctx, req, http.MethodPost, action, map[string]any{
		"Image": req.MediaURL, "Inserted": true, "WriteProtected": true,
	}, nil)
}

func (p *RedfishProvider) Attach(req Request) error { return p.AttachContext(p.ctx(), req) }

func (p *RedfishProvider) SetOneTimeBootContext(ctx context.Context, req Request) error {
	var current redfishSystem
	if err := p.requestContext(ctx, req, http.MethodGet, req.SystemResource, nil, &current); err != nil {
		return err
	}
	if strings.EqualFold(current.Boot.Enabled, "Once") && (strings.EqualFold(current.Boot.Target, "Cd") || strings.EqualFold(current.Boot.Target, "Usb")) {
		return nil
	}
	return p.requestContext(ctx, req, http.MethodPatch, req.SystemResource, map[string]any{
		"Boot": map[string]any{"BootSourceOverrideEnabled": "Once", "BootSourceOverrideTarget": "Cd"},
	}, nil)
}

func (p *RedfishProvider) SetOneTimeBoot(req Request) error {
	return p.SetOneTimeBootContext(p.ctx(), req)
}

func (p *RedfishProvider) PowerCycleContext(ctx context.Context, req Request) error {
	var current redfishSystem
	if err := p.requestContext(ctx, req, http.MethodGet, req.SystemResource, nil, &current); err != nil {
		return err
	}
	resetType := "ForceRestart"
	if strings.EqualFold(current.PowerState, "Off") {
		resetType = "On"
	}
	action := strings.TrimSuffix(req.SystemResource, "/") + "/Actions/ComputerSystem.Reset"
	return p.requestContext(ctx, req, http.MethodPost, action, map[string]any{"ResetType": resetType}, nil)
}

func (p *RedfishProvider) PowerCycle(req Request) error { return p.PowerCycleContext(p.ctx(), req) }

func (p *RedfishProvider) ObserveContext(ctx context.Context, req Request) (Observation, error) {
	var media redfishVirtualMedia
	if err := p.requestContext(ctx, req, http.MethodGet, req.VirtualMediaResource, nil, &media); err != nil {
		return Observation{}, err
	}
	var system redfishSystem
	if err := p.requestContext(ctx, req, http.MethodGet, req.SystemResource, nil, &system); err != nil {
		return Observation{}, err
	}
	attached := media.Inserted && media.Image == req.MediaURL
	oneTime := strings.EqualFold(system.Boot.Enabled, "Once") && (strings.EqualFold(system.Boot.Target, "Cd") || strings.EqualFold(system.Boot.Target, "Usb"))
	powered := !strings.EqualFold(system.PowerState, "Off") && strings.TrimSpace(system.PowerState) != ""
	bootState := strings.ToUpper(strings.TrimSpace(system.PowerState))
	if bootState == "" {
		bootState = "UNKNOWN"
	}
	return Observation{Attached: attached, OneTimeBootSet: oneTime, Powered: powered, BootState: "REDFISH_" + bootState}, nil
}

func (p *RedfishProvider) Observe(req Request) (Observation, error) {
	return p.ObserveContext(p.ctx(), req)
}
