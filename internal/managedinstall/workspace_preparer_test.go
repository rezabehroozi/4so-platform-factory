package managedinstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type preparationSecrets map[string][]byte
func (s preparationSecrets) ResolveManagedOKDPreparationSecret(_ context.Context, _, _, ref string)([]byte,error){
	return append([]byte(nil),s[ref]...),nil
}
func prepRequest() PreparationRequest {
	return PreparationRequest{
		OrganizationID:"org-1",ProjectID:"project-1",TargetVersion:"4.19.0",ClusterName:"prod-a",BaseDomain:"example.test",
		APIVIP:"10.0.0.10",IngressVIP:"10.0.0.11",MachineNetwork:"10.0.0.0/24",RendezvousIP:"10.0.0.20",
		PullSecretRef:"pull-secret-prod-a",SSHKeyRef:"ssh-key-prod-a",
		Machines:testRequest().Machines,
		Hosts:[]PreparationHost{
			{MachineID:"cp-1",Hostname:"cp-1",Interfaces:[]PreparationInterface{{Name:"eno1",MACAddress:"02:00:00:00:00:01"}},NetworkConfig:map[string]any{"interfaces":[]any{map[string]any{"name":"eno1","type":"ethernet","state":"up"}}}},
			{MachineID:"cp-2",Hostname:"cp-2",Interfaces:[]PreparationInterface{{Name:"eno1",MACAddress:"02:00:00:00:00:02"}},NetworkConfig:map[string]any{"interfaces":[]any{map[string]any{"name":"eno1","type":"ethernet","state":"up"}}}},
			{MachineID:"cp-3",Hostname:"cp-3",Interfaces:[]PreparationInterface{{Name:"eno1",MACAddress:"02:00:00:00:00:03"}},NetworkConfig:map[string]any{"interfaces":[]any{map[string]any{"name":"eno1","type":"ethernet","state":"up"}}}},
		},
	}
}
func TestWorkspacePreparerGeneratesContentAddressedFinalRequestWithoutSecretLeak(t *testing.T){
	root:=t.TempDir(); workspaceRoot:=filepath.Join(root,"workspaces"); mediaRoot:=filepath.Join(root,"media"); binRoot:=filepath.Join(root,"bin")
	for _,d:=range []string{workspaceRoot,mediaRoot,binRoot}{if err:=os.MkdirAll(d,0o700);err!=nil{t.Fatal(err)};_ = os.Chmod(d,0o700)}
	body:=`#!/bin/sh
set -eu
case "$*" in
  *"agent create image"*)
    test -f install-config.yaml
    test -f agent-config.yaml
    grep -q '"pullSecret"' install-config.yaml
    grep -q '"rendezvousIP"' agent-config.yaml
    mkdir -p auth
    printf 'apiVersion: v1\nkind: Config\n' >auth/kubeconfig
    printf 'fake-agent-iso-%s\n' "$OPENSHIFT_INSTALL_RELEASE_IMAGE_OVERRIDE" >agent.x86_64.iso
    ;;
  *) exit 42 ;;
esac
`
	installPath,installSHA:=writeExecutableFixture(t,binRoot,"openshift-install",body)
	releaseDigest:="sha256:"+strings.Repeat("a",64); osDigest:="sha256:"+strings.Repeat("b",64)
	preparer:=&WorkspacePreparer{Config:WorkspacePreparerConfig{
		WorkspaceRoot:workspaceRoot,MediaRoot:mediaRoot,AgentISOArtifactBaseURL:"https://platform.example.test/managed-install-media",
		OpenShiftInstall:installPath,OpenShiftInstallSHA:installSHA,
		ReleasePayload:Artifact{Name:"release-payload",Version:"4.19.0",URL:"https://quay.io/v2/okd/scos-release/manifests/sha256:"+strings.Repeat("a",64),SHA256:releaseDigest},
		MachineOS:Artifact{Name:"fcos",Version:"9.0.20250510-0",URL:"https://mirror.example.test/scos.raw.gz",SHA256:osDigest},
		CommandTimeout:time.Minute,PreparedBy:"platform-api",
	},Secrets:preparationSecrets{
		"pull-secret-prod-a":[]byte(`{"auths":{"quay.io":{"auth":"TOPSECRET"}}}`),
		"ssh-key-prod-a":[]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey"),
	}}
	result,err:=preparer.PrepareConnected(context.Background(),prepRequest());if err!=nil{t.Fatal(err)}
	if err=ValidateRequest(result.Request);err!=nil{t.Fatal(err)}
	if result.Evidence.SecretMaterialPersisted || result.Evidence.RuntimeCertified || result.Evidence.PhysicalCertified {t.Fatalf("inflated evidence %#v",result.Evidence)}
	raw,_:=json.Marshal(result)
	if strings.Contains(string(raw),"TOPSECRET") || strings.Contains(string(raw),"AAAAC3Nza"){t.Fatal("secret material leaked into result")}
	iso:=Artifact{};for _,a:=range result.Request.Artifacts{if a.Name=="agent-iso"{iso=a}}
	if iso.SHA256=="" || !strings.Contains(iso.URL,strings.TrimPrefix(iso.SHA256,"sha256:")){t.Fatalf("bad ISO artifact %#v",iso)}
	hexDigest:=strings.TrimPrefix(iso.SHA256,"sha256:")
	content,err:=os.ReadFile(filepath.Join(mediaRoot,"sha256",hexDigest,"agent.iso"));if err!=nil{t.Fatal(err)}
	sum:=sha256.Sum256(content);if hex.EncodeToString(sum[:])!=hexDigest{t.Fatal("content-addressed media digest mismatch")}
	ws:=filepath.Join(workspaceRoot,"sha256",strings.TrimPrefix(result.Evidence.RequestDigest,"sha256:"))
	if _,err=os.Stat(filepath.Join(ws,"workspace.json"));err!=nil{t.Fatal(err)}
	if _,err=os.Stat(filepath.Join(ws,"install-config.yaml"));!os.IsNotExist(err){t.Fatal("secret-bearing install-config persisted")}
	if _,err=os.Stat(filepath.Join(ws,"agent-config.yaml"));!os.IsNotExist(err){t.Fatal("agent-config persisted after workspace seal")}
}
func TestWorkspacePreparerRejectsInvalidTopologyBeforeSecretResolution(t *testing.T){
	req:=prepRequest();req.Hosts[1].MachineID="cp-1"
	if _,err:=canonicalPreparationRequest(req);err==nil{t.Fatal("duplicate host mapping accepted")}
	req=prepRequest();req.RendezvousIP="192.0.2.10"
	if _,err:=canonicalPreparationRequest(req);err==nil{t.Fatal("rendezvous outside machine network accepted")}
	req=prepRequest();req.PullSecretRef="secret://raw"
	if _,err:=canonicalPreparationRequest(req);err==nil{t.Fatal("secret URL accepted instead of opaque reference")}
}
