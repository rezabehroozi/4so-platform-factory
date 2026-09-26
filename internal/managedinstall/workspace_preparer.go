package managedinstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const WorkspacePreparationAuthority = "MANAGED_OKD_AGENT_WORKSPACE_PREPARATION_V1"

type PreparationSecretResolver interface {
	ResolveManagedOKDPreparationSecret(context.Context, string, string, string) ([]byte, error)
}

type PreparationInterface struct {
	Name       string `json:"name"`
	MACAddress string `json:"macAddress"`
}

type PreparationHost struct {
	MachineID     string                 `json:"machineId"`
	Hostname      string                 `json:"hostname"`
	Interfaces    []PreparationInterface `json:"interfaces"`
	NetworkConfig map[string]any         `json:"networkConfig"`
}

type PreparationRequest struct {
	OrganizationID string            `json:"organizationId"`
	ProjectID      string            `json:"projectId"`
	TargetVersion  string            `json:"targetVersion"`
	ClusterName    string            `json:"clusterName"`
	BaseDomain     string            `json:"baseDomain"`
	APIVIP         string            `json:"apiVip"`
	IngressVIP     string            `json:"ingressVip"`
	MachineNetwork string            `json:"machineNetworkCidr"`
	RendezvousIP   string            `json:"rendezvousIp"`
	PullSecretRef  string            `json:"pullSecretRef"`
	SSHKeyRef      string            `json:"sshKeyRef"`
	Machines       []Machine         `json:"machines"`
	Hosts          []PreparationHost `json:"hosts"`
}

type WorkspacePreparerConfig struct {
	WorkspaceRoot       string
	MediaRoot           string
	AgentISOArtifactBaseURL string
	OpenShiftInstall    string
	OpenShiftInstallSHA string
	ReleasePayload      Artifact
	MachineOS           Artifact
	CommandTimeout      time.Duration
	PreparedBy          string
}

type WorkspacePreparer struct {
	Config  WorkspacePreparerConfig
	Secrets PreparationSecretResolver
}

type WorkspacePreparationEvidence struct {
	Authority             string   `json:"authority"`
	PreparationDigest     string   `json:"preparationDigest"`
	RequestDigest         string   `json:"requestDigest"`
	TargetVersion         string   `json:"targetVersion"`
	ClusterName           string   `json:"clusterName"`
	OpenShiftInstallSHA   string   `json:"openshiftInstallSha256"`
	ReleasePayloadSHA     string   `json:"releasePayloadSha256"`
	MachineOSSHA          string   `json:"machineOsSha256"`
	AgentISOSHA           string   `json:"agentIsoSha256"`
	AgentISOBytes         int64    `json:"agentIsoBytes"`
	WorkspaceAuthority    string   `json:"workspaceAuthority"`
	MediaAuthority        string   `json:"mediaAuthority"`
	Hostnames             []string `json:"hostnames"`
	SecretMaterialPersisted bool   `json:"secretMaterialPersisted"`
	RuntimeCertified      bool     `json:"runtimeCertified"`
	PhysicalCertified     bool     `json:"physicalCertified"`
}

type WorkspacePreparationResult struct {
	Request  Request                      `json:"request"`
	Evidence WorkspacePreparationEvidence `json:"evidence"`
}

func canonicalOpaqueSecretRef(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "=\r\n\t") || strings.Contains(value, "://") || strings.ContainsAny(value, " /\\") {
		return "", errors.New("preparation secret reference must be an opaque identifier")
	}
	return value, nil
}

func canonicalMAC(value string) (string, error) {
	hw, err := net.ParseMAC(strings.TrimSpace(value))
	if err != nil || len(hw) != 6 {
		return "", errors.New("host interface requires an exact 48-bit MAC address")
	}
	return strings.ToLower(hw.String()), nil
}

func canonicalPreparationRequest(req PreparationRequest) (PreparationRequest, error) {
	req.OrganizationID = strings.TrimSpace(req.OrganizationID)
	req.ProjectID = strings.TrimSpace(req.ProjectID)
	req.TargetVersion = strings.TrimSpace(req.TargetVersion)
	req.ClusterName = strings.ToLower(strings.TrimSpace(req.ClusterName))
	req.BaseDomain = strings.ToLower(strings.TrimSpace(req.BaseDomain))
	req.APIVIP = strings.TrimSpace(req.APIVIP)
	req.IngressVIP = strings.TrimSpace(req.IngressVIP)
	req.MachineNetwork = strings.TrimSpace(req.MachineNetwork)
	req.RendezvousIP = strings.TrimSpace(req.RendezvousIP)
	var err error
	if req.PullSecretRef, err = canonicalOpaqueSecretRef(req.PullSecretRef); err != nil { return PreparationRequest{}, err }
	if req.SSHKeyRef, err = canonicalOpaqueSecretRef(req.SSHKeyRef); err != nil { return PreparationRequest{}, err }
	if len(req.Machines) != 3 || len(req.Hosts) != 3 {
		return PreparationRequest{}, errors.New("Compact-3 preparation requires exactly three machines and three hosts")
	}
	machineByID := map[string]bool{}
	for i := range req.Machines {
		m := &req.Machines[i]
		m.ID = strings.TrimSpace(m.ID)
		m.CredentialRef = strings.TrimSpace(m.CredentialRef)
		m.Endpoint = strings.TrimRight(strings.TrimSpace(m.Endpoint), "/")
		m.SystemResource = strings.TrimSpace(m.SystemResource)
		m.VirtualMediaResource = strings.TrimSpace(m.VirtualMediaResource)
		if m.ID == "" || machineByID[m.ID] { return PreparationRequest{}, errors.New("preparation machine ids must be unique and non-empty") }
		machineByID[m.ID] = true
	}
	hostByMachine := map[string]bool{}
	hostnames := map[string]bool{}
	for i := range req.Hosts {
		h := &req.Hosts[i]
		h.MachineID = strings.TrimSpace(h.MachineID)
		h.Hostname = strings.ToLower(strings.TrimSpace(h.Hostname))
		if !machineByID[h.MachineID] || hostByMachine[h.MachineID] || h.Hostname == "" || hostnames[h.Hostname] {
			return PreparationRequest{}, errors.New("preparation host identity must map one-to-one to machines")
		}
		if len(h.Interfaces) == 0 || len(h.NetworkConfig) == 0 {
			return PreparationRequest{}, fmt.Errorf("host %s requires interfaces and nmstate networkConfig", h.MachineID)
		}
		hostByMachine[h.MachineID] = true
		hostnames[h.Hostname] = true
		ifaces := map[string]bool{}
		macs := map[string]bool{}
		for j := range h.Interfaces {
			iface := &h.Interfaces[j]
			iface.Name = strings.TrimSpace(iface.Name)
			if iface.Name == "" || ifaces[iface.Name] { return PreparationRequest{}, fmt.Errorf("host %s has invalid interface identity", h.MachineID) }
			iface.MACAddress, err = canonicalMAC(iface.MACAddress)
			if err != nil || macs[iface.MACAddress] { return PreparationRequest{}, fmt.Errorf("host %s has invalid or duplicate interface MAC", h.MachineID) }
			ifaces[iface.Name] = true
			macs[iface.MACAddress] = true
		}
		sort.Slice(h.Interfaces, func(a,b int) bool { return h.Interfaces[a].Name < h.Interfaces[b].Name })
	}
	if req.OrganizationID=="" || req.ProjectID=="" || req.TargetVersion=="" || req.ClusterName=="" || req.BaseDomain=="" || req.APIVIP=="" || req.IngressVIP=="" {
		return PreparationRequest{}, errors.New("preparation organization/project/cluster/version/domain/VIPs are required")
	}
	if net.ParseIP(req.APIVIP)==nil || net.ParseIP(req.IngressVIP)==nil || req.APIVIP==req.IngressVIP || net.ParseIP(req.RendezvousIP)==nil {
		return PreparationRequest{}, errors.New("preparation API/Ingress/rendezvous IP values are invalid")
	}
	_, network, err := net.ParseCIDR(req.MachineNetwork)
	if err != nil || !network.Contains(net.ParseIP(req.RendezvousIP)) {
		return PreparationRequest{}, errors.New("rendezvous IP must belong to machineNetworkCidr")
	}
	sort.Slice(req.Machines, func(i,j int) bool { return req.Machines[i].ID < req.Machines[j].ID })
	sort.Slice(req.Hosts, func(i,j int) bool { return req.Hosts[i].MachineID < req.Hosts[j].MachineID })
	// Reuse the final request validator for all BMC authority semantics.
	probe := Request{OrganizationID:req.OrganizationID,ProjectID:req.ProjectID,TargetVersion:req.TargetVersion,ClusterName:req.ClusterName,BaseDomain:req.BaseDomain,APIVIP:req.APIVIP,IngressVIP:req.IngressVIP,Machines:req.Machines,Artifacts:[]Artifact{
		{Name:"release-payload",Version:req.TargetVersion,URL:"https://preparation.invalid/release",SHA256:"sha256:"+strings.Repeat("a",64)},
		{Name:"fcos",Version:"machine-os",URL:"https://preparation.invalid/machine-os",SHA256:"sha256:"+strings.Repeat("b",64)},
		{Name:"agent-iso",Version:req.TargetVersion,URL:"https://preparation.invalid/agent.iso",SHA256:"sha256:"+strings.Repeat("c",64)},
	}}
	if err=ValidateRequest(probe); err!=nil { return PreparationRequest{}, fmt.Errorf("preparation request: %w",err) }
	return req,nil
}

func preparationDigest(req PreparationRequest) (string,error) {
	c,err:=canonicalPreparationRequest(req); if err!=nil{return "",err}
	raw,_:=json.Marshal(struct{Authority string `json:"authority"`; Request PreparationRequest `json:"request"`}{WorkspacePreparationAuthority,c})
	sum:=sha256.Sum256(raw)
	return "sha256:"+hex.EncodeToString(sum[:]),nil
}

func preparationArtifactURL(base, digest string) (string,error) {
	base=strings.TrimRight(strings.TrimSpace(base),"/")
	u,err:=url.Parse(base)
	if err!=nil || u.Scheme!="https" || u.Host=="" || u.User!=nil || u.RawQuery!="" || u.Fragment!="" {
		return "",errors.New("agent ISO artifact base URL must be canonical credential-free HTTPS")
	}
	return base+"/sha256/"+strings.TrimPrefix(digest,"sha256:")+"/agent.iso",nil
}

func writePrivateJSON(path string, value any) error {
	raw,err:=json.MarshalIndent(value,"","  "); if err!=nil{return err}; raw=append(raw,'\n')
	return os.WriteFile(path,raw,0o600)
}

func hashAndCopyISO(srcPath, mediaRoot string) (string,int64,error) {
	before,err:=os.Lstat(srcPath); if err!=nil{return "",0,err}
	if before.Mode()&os.ModeSymlink!=0 || !before.Mode().IsRegular(){return "",0,errors.New("generated Agent ISO must be a regular non-symlink file")}
	if before.Mode().Perm()&0o077!=0 {
		if err=os.Chmod(srcPath,0o600);err!=nil{return "",0,fmt.Errorf("harden generated Agent ISO permissions: %w",err)}
	}
	src,info,err:=secureOpenRegular(srcPath,true); if err!=nil{return "",0,err}; defer src.Close()
	if info.Size()<=0 || info.Size()>4<<30{return "",0,errors.New("generated Agent ISO byte size is invalid")}
	h:=sha256.New()
	tmpRoot,err:=secureDir(mediaRoot,true); if err!=nil{return "",0,err}
	tmp,err:=os.CreateTemp(tmpRoot,"agent-iso-*.tmp"); if err!=nil{return "",0,err}
	tmpPath:=tmp.Name(); cleanup:=true
	defer func(){_ = tmp.Close(); if cleanup {_=os.Remove(tmpPath)}}()
	if err=os.Chmod(tmpPath,0o600);err!=nil{return "",0,err}
	written,err:=io.Copy(io.MultiWriter(tmp,h),src);if err!=nil{return "",0,err}
	if written!=info.Size(){return "",0,errors.New("generated Agent ISO changed while copying")}
	if err=tmp.Sync();err!=nil{return "",0,err}; if err=tmp.Close();err!=nil{return "",0,err}
	digest:=hex.EncodeToString(h.Sum(nil))
	destDir:=filepath.Join(tmpRoot,"sha256",digest)
	if err=os.MkdirAll(destDir,0o700);err!=nil{return "",0,err}; if err=os.Chmod(destDir,0o700);err!=nil{return "",0,err}
	dest:=filepath.Join(destDir,"agent.iso")
	if existing,existingInfo,openErr:=secureOpenRegular(dest,true);openErr==nil {
		got,hashErr:=hashOpenFile(existing);_ = existing.Close()
		if hashErr!=nil || got!=digest || existingInfo.Size()!=written{return "",0,errors.New("existing content-addressed Agent ISO conflicts with generated bytes")}
		cleanup=true
		return "sha256:"+digest,written,nil
	} else if !errors.Is(openErr,os.ErrNotExist){return "",0,openErr}
	if err=os.Rename(tmpPath,dest);err!=nil{return "",0,err}; cleanup=false
	return "sha256:"+digest,written,nil
}

func (p *WorkspacePreparer) PrepareConnected(ctx context.Context, req PreparationRequest) (WorkspacePreparationResult,error) {
	if p==nil || p.Secrets==nil{return WorkspacePreparationResult{},errors.New("managed OKD workspace preparer secret resolver is required")}
	c,err:=canonicalPreparationRequest(req);if err!=nil{return WorkspacePreparationResult{},err}
	if strings.TrimSpace(p.Config.PreparedBy)==""{return WorkspacePreparationResult{},errors.New("workspace preparer identity is required")}
	root,err:=secureDir(p.Config.WorkspaceRoot,true);if err!=nil{return WorkspacePreparationResult{},fmt.Errorf("workspace root: %w",err)}
	mediaRoot,err:=secureDir(p.Config.MediaRoot,true);if err!=nil{return WorkspacePreparationResult{},fmt.Errorf("media root: %w",err)}
	_ = mediaRoot
	install,_,installDigest,err:=verifiedBinary(p.Config.OpenShiftInstall,p.Config.OpenShiftInstallSHA);if err!=nil{return WorkspacePreparationResult{},fmt.Errorf("openshift-install exact binary: %w",err)};_ = install.Close()
	release:=p.Config.ReleasePayload; machineOS:=p.Config.MachineOS
	if release.Name!="release-payload" || release.Version!=c.TargetVersion || machineOS.Name!="fcos" {
		return WorkspacePreparationResult{},errors.New("preparer exact release payload/machine OS authority is invalid")
	}
	if _,err=normalizeExpectedDigest(release.SHA256);err!=nil{return WorkspacePreparationResult{},err}
	if _,err=normalizeExpectedDigest(machineOS.SHA256);err!=nil{return WorkspacePreparationResult{},err}
	prepDigest,err:=preparationDigest(c);if err!=nil{return WorkspacePreparationResult{},err}
	pullSecret,err:=p.Secrets.ResolveManagedOKDPreparationSecret(ctx,c.OrganizationID,c.ProjectID,c.PullSecretRef);if err!=nil{return WorkspacePreparationResult{},fmt.Errorf("resolve pull secret: %w",err)}
	sshKey,err:=p.Secrets.ResolveManagedOKDPreparationSecret(ctx,c.OrganizationID,c.ProjectID,c.SSHKeyRef);if err!=nil{return WorkspacePreparationResult{},fmt.Errorf("resolve SSH key: %w",err)}
	defer func(){for i:=range pullSecret{pullSecret[i]=0};for i:=range sshKey{sshKey[i]=0}}()
	if len(strings.TrimSpace(string(pullSecret)))<2 || len(strings.TrimSpace(string(sshKey)))<16{return WorkspacePreparationResult{},errors.New("resolved preparation secret material is invalid")}
	tmp,err:=os.MkdirTemp(root,".prepare-");if err!=nil{return WorkspacePreparationResult{},err}
	if err=os.Chmod(tmp,0o700);err!=nil{_ = os.RemoveAll(tmp);return WorkspacePreparationResult{},err}
	cleanup:=true;defer func(){if cleanup{_ = os.RemoveAll(tmp)}}()
	installConfig:=map[string]any{
		"apiVersion":"v1","baseDomain":c.BaseDomain,
		"metadata":map[string]any{"name":c.ClusterName},
		"compute":[]any{map[string]any{"name":"worker","replicas":0}},
		"controlPlane":map[string]any{"name":"master","replicas":3},
		"networking":map[string]any{"machineNetwork":[]any{map[string]any{"cidr":c.MachineNetwork}}},
		"platform":map[string]any{"none":map[string]any{}},
		"pullSecret":strings.TrimSpace(string(pullSecret)),"sshKey":strings.TrimSpace(string(sshKey)),
	}
	hosts:=make([]any,0,len(c.Hosts))
	for _,h:=range c.Hosts{
		ifaces:=make([]any,0,len(h.Interfaces));for _,iface:=range h.Interfaces{ifaces=append(ifaces,map[string]any{"name":iface.Name,"macAddress":iface.MACAddress})}
		hosts=append(hosts,map[string]any{"hostname":h.Hostname,"role":"master","interfaces":ifaces,"networkConfig":h.NetworkConfig})
	}
	agentConfig:=map[string]any{"apiVersion":"v1beta1","kind":"AgentConfig","metadata":map[string]any{"name":c.ClusterName},"rendezvousIP":c.RendezvousIP,"hosts":hosts}
	if err=writePrivateJSON(filepath.Join(tmp,"install-config.yaml"),installConfig);err!=nil{return WorkspacePreparationResult{},err}
	if err=writePrivateJSON(filepath.Join(tmp,"agent-config.yaml"),agentConfig);err!=nil{return WorkspacePreparationResult{},err}
	commandCtx,cancel:=context.WithTimeout(ctx,func()time.Duration{if p.Config.CommandTimeout>0{return p.Config.CommandTimeout};return 20*time.Minute}());defer cancel()
	binCopy:=filepath.Join(tmp,"openshift-install")
	if _,err=copyVerifiedExecutable(p.Config.OpenShiftInstall,p.Config.OpenShiftInstallSHA,binCopy);err!=nil{return WorkspacePreparationResult{},err}
	env:=sanitizedCommandEnv()
	// Bind the exact release payload. Machine OS selection remains installer-owned
	// and is cross-checked against the separately sealed machineOS authority.
	env=append(env,"OPENSHIFT_INSTALL_RELEASE_IMAGE_OVERRIDE="+strings.TrimSpace(release.URL))
	if _,err=runBoundedEnv(commandCtx,tmp,binCopy,env,nil,"agent","create","image","--dir",tmp,"--log-level=info");err!=nil{return WorkspacePreparationResult{},fmt.Errorf("generate exact Agent ISO: %w",err)}
	matches,err:=filepath.Glob(filepath.Join(tmp,"agent*.iso"));if err!=nil||len(matches)!=1{return WorkspacePreparationResult{},fmt.Errorf("generated Agent ISO coverage invalid: %d",len(matches))}
	isoDigest,isoBytes,err:=hashAndCopyISO(matches[0],p.Config.MediaRoot);if err!=nil{return WorkspacePreparationResult{},fmt.Errorf("seal Agent ISO: %w",err)}
	isoURL,err:=preparationArtifactURL(p.Config.AgentISOArtifactBaseURL,isoDigest);if err!=nil{return WorkspacePreparationResult{},err}
	finalReq:=Request{OrganizationID:c.OrganizationID,ProjectID:c.ProjectID,TargetVersion:c.TargetVersion,ClusterName:c.ClusterName,BaseDomain:c.BaseDomain,APIVIP:c.APIVIP,IngressVIP:c.IngressVIP,Connectivity:"connected",Machines:c.Machines,Artifacts:[]Artifact{
		release,machineOS,{Name:"agent-iso",Version:c.TargetVersion,URL:isoURL,SHA256:isoDigest},
	}}
	finalReq,err=CanonicalRequest(finalReq);if err!=nil{return WorkspacePreparationResult{},err}
	finalPath,requestDigest,err:=workspacePath(root,finalReq);if err!=nil{return WorkspacePreparationResult{},err}
	if _,statErr:=os.Lstat(finalPath);statErr==nil{return WorkspacePreparationResult{},errors.New("exact managed OKD workspace already exists; refusing non-idempotent overwrite")}else if !errors.Is(statErr,os.ErrNotExist){return WorkspacePreparationResult{},statErr}
	// Generated install workspace may contain auth assets needed by later wait/health
	// operations. Remove the transient executable and secret-bearing source configs
	// before sealing the workspace authority.
	_ = os.Remove(binCopy)
	_ = os.Remove(filepath.Join(tmp,"install-config.yaml"))
	_ = os.Remove(filepath.Join(tmp,"agent-config.yaml"))
	_ = os.Remove(matches[0])
	desc:=WorkspaceDescriptor{Authority:WorkspaceDescriptorAuthority,RequestDigest:requestDigest,OrganizationID:c.OrganizationID,ProjectID:c.ProjectID,ClusterName:c.ClusterName,TargetVersion:c.TargetVersion,ReleasePayloadSHA:release.SHA256,FCOSSHA:machineOS.SHA256,AgentISOSHA:isoDigest,PreparedBy:strings.TrimSpace(p.Config.PreparedBy),PreparationVersion:"v1"}
	if err=writePrivateJSON(filepath.Join(tmp,"workspace.json"),desc);err!=nil{return WorkspacePreparationResult{},err}
	if err=validateWorkspaceTree(tmp);err!=nil{return WorkspacePreparationResult{},err}
	parent:=filepath.Dir(finalPath);if err=os.MkdirAll(parent,0o700);err!=nil{return WorkspacePreparationResult{},err};if err=os.Chmod(parent,0o700);err!=nil{return WorkspacePreparationResult{},err}
	if err=os.Rename(tmp,finalPath);err!=nil{return WorkspacePreparationResult{},err};cleanup=false
	hostnames:=make([]string,0,len(c.Hosts));for _,h:=range c.Hosts{hostnames=append(hostnames,h.Hostname)};sort.Strings(hostnames)
	return WorkspacePreparationResult{Request:finalReq,Evidence:WorkspacePreparationEvidence{
		Authority:WorkspacePreparationAuthority,PreparationDigest:prepDigest,RequestDigest:requestDigest,TargetVersion:c.TargetVersion,ClusterName:c.ClusterName,
		OpenShiftInstallSHA:"sha256:"+installDigest,ReleasePayloadSHA:release.SHA256,MachineOSSHA:machineOS.SHA256,AgentISOSHA:isoDigest,AgentISOBytes:isoBytes,
		WorkspaceAuthority:WorkspaceDescriptorAuthority,MediaAuthority:MediaStoreAuthority,Hostnames:hostnames,SecretMaterialPersisted:false,RuntimeCertified:false,PhysicalCertified:false,
	}},nil
}

func secureWriteFixtureGuard(path string) error {
	info,err:=os.Lstat(path);if err!=nil{return err}
	if info.Mode()&os.ModeSymlink!=0 || !info.Mode().IsRegular(){return errors.New("unsafe preparation output")}
	fd,err:=syscall.Open(path,syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0);if err!=nil{return err};return syscall.Close(fd)
}
