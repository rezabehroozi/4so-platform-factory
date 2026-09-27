package managedinstall

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type exactWorkspaceSecretResolver struct{ pull, ssh []byte }
func (r exactWorkspaceSecretResolver) ResolveManagedOKDPreparationSecret(_ context.Context, _, _, ref string) ([]byte,error) {
	switch ref {
	case "pull-secret-ref": return append([]byte(nil),r.pull...),nil
	case "ssh-key-ref": return append([]byte(nil),r.ssh...),nil
	default: return nil,os.ErrNotExist
	}
}

func TestExactOKDAgentWorkspaceExecution(t *testing.T) {
	installer:=strings.TrimSpace(os.Getenv("OKD_EXACT_INSTALLER"))
	if installer=="" { t.Skip("exact OKD installer execution is an explicit CI lane") }
	required:=func(name string) string { v:=strings.TrimSpace(os.Getenv(name)); if v=="" { t.Fatalf("%s is required",name) }; return v }
	installerSHA:=required("OKD_EXACT_INSTALLER_SHA")
	releaseImage:=required("OKD_EXACT_RELEASE_IMAGE")
	releaseSHA:=required("OKD_EXACT_RELEASE_SHA")
	machineURL:=required("OKD_EXACT_MACHINE_OS_URL")
	machineSHA:=required("OKD_EXACT_MACHINE_OS_SHA")
	pull:=required("OKD_TEST_PULL_SECRET")
	ssh:=required("OKD_TEST_SSH_KEY")
	workspaceRoot:=required("OKD_AGENT_WORKSPACE_ROOT")
	mediaRoot:=required("OKD_AGENT_MEDIA_ROOT")
	out:=required("OKD_AGENT_EVIDENCE_OUT")
	for _, root := range []string{workspaceRoot, mediaRoot} {
		if err := os.MkdirAll(root, 0o700); err != nil { t.Fatal(err) }
		if err := os.Chmod(root, 0o700); err != nil { t.Fatal(err) }
	}
	hosts:=[]PreparationHost{}
	machines:=[]Machine{}
	for i:=0;i<3;i++ {
		id:=[]string{"node-a","node-b","node-c"}[i]
		ip:=[]string{"192.168.111.21","192.168.111.22","192.168.111.23"}[i]
		mac:=[]string{"02:00:00:00:00:21","02:00:00:00:00:22","02:00:00:00:00:23"}[i]
		machines=append(machines,Machine{ID:id,CredentialRef:"bmc-"+id,Endpoint:"https://"+id+".bmc.example.test",SystemResource:"/redfish/v1/Systems/1",VirtualMediaResource:"/redfish/v1/Managers/1/VirtualMedia/CD"})
		hosts=append(hosts,PreparationHost{MachineID:id,Hostname:id,Interfaces:[]PreparationInterface{{Name:"eno1",MACAddress:mac}},NetworkConfig:map[string]any{
			"interfaces":[]any{map[string]any{"name":"eno1","type":"ethernet","state":"up","mac-address":mac,"ipv4":map[string]any{"enabled":true,"address":[]any{map[string]any{"ip":ip,"prefix-length":24}}}}},
			"routes":map[string]any{"config":[]any{map[string]any{"destination":"0.0.0.0/0","next-hop-address":"192.168.111.1","next-hop-interface":"eno1"}}},
			"dns-resolver":map[string]any{"config":map[string]any{"server":[]any{"192.168.111.1"}}},
		}})
	}
	p:=WorkspacePreparer{Config:WorkspacePreparerConfig{
		WorkspaceRoot:workspaceRoot,MediaRoot:mediaRoot,AgentISOArtifactBaseURL:"https://media.example.test/managed-okd",
		OpenShiftInstall:installer,OpenShiftInstallSHA:installerSHA,
		ReleasePayload:Artifact{Name:"release-payload",Version:"4.19.0",URL:"https://quay.io/okd/scos-release",SHA256:releaseSHA},
		ReleaseImageReference:releaseImage,
		MachineOS:Artifact{Name:"fcos",Version:"9.0.20250510-0",URL:machineURL,SHA256:machineSHA},
		CommandTimeout:35*time.Minute,PreparedBy:"github-actions-exact-okd-agent-workspace",
	},Secrets:exactWorkspaceSecretResolver{pull:[]byte(pull),ssh:[]byte(ssh)}}
	result,err:=p.PrepareConnected(context.Background(),PreparationRequest{
		OrganizationID:"org-cert",ProjectID:"project-cert",TargetVersion:"4.19.0",ClusterName:"cert-okd",BaseDomain:"example.test",
		APIVIP:"192.168.111.5",IngressVIP:"192.168.111.6",MachineNetwork:"192.168.111.0/24",RendezvousIP:"192.168.111.21",
		PullSecretRef:"pull-secret-ref",SSHKeyRef:"ssh-key-ref",Machines:machines,Hosts:hosts,
	})
	if err!=nil { t.Fatal(err) }
	ev:=result.Evidence
	if ev.Authority!=WorkspacePreparationAuthority || ev.WorkspaceAuthority!=WorkspaceDescriptorAuthority || ev.MediaAuthority!=MediaStoreAuthority { t.Fatalf("authority drift: %#v",ev) }
	if ev.OpenShiftInstallSHA!="sha256:"+strings.TrimPrefix(installerSHA,"sha256:") || ev.ReleasePayloadSHA!=releaseSHA || ev.MachineOSSHA!=machineSHA { t.Fatalf("exact source binding drift: %#v",ev) }
	if !strings.HasPrefix(ev.AgentISOSHA,"sha256:") || ev.AgentISOBytes<=0 || ev.SecretMaterialPersisted || ev.RuntimeCertified || ev.PhysicalCertified { t.Fatalf("claim scope drift: %#v",ev) }
	iso:=filepath.Join(mediaRoot,"sha256",strings.TrimPrefix(ev.AgentISOSHA,"sha256:"),"agent.iso")
	if info,err:=os.Lstat(iso);err!=nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink!=0 || info.Size()!=ev.AgentISOBytes { t.Fatalf("sealed ISO invalid: %v %#v",err,info) }
	payload:=map[string]any{"apiVersion":"platform.4so.io/v1alpha1","kind":"ManagedOKDAgentWorkspaceExecutionEvidence","authority":"MANAGED_OKD_AGENT_WORKSPACE_EXECUTION_EVIDENCE_V1","preparation":ev,"requestDigest":ev.RequestDigest,"agentISOPathConvention":"sha256/<agentIsoSha256>/agent.iso","requestSpecificMedia":true,"exactUpstreamExecution":true,"redfishBootExecuted":false,"clusterInstallExecuted":false,"runtimeCertified":false,"physicalCertified":false}
	raw,_:=json.MarshalIndent(payload,"","  "); raw=append(raw,'\n')
	if err=os.WriteFile(out,raw,0o600);err!=nil { t.Fatal(err) }
}
