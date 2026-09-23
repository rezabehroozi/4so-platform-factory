package controlplane

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

const (
	applicationAuthorityWorkloadType        = "WORKLOAD_TYPE"
	applicationAuthorityCapabilityTrait     = "CAPABILITY_TRAIT"
	applicationAuthorityManagedResourceType = "MANAGED_RESOURCE_TYPE"
	applicationAuthorityWorkspaceProfile    = "WORKSPACE_PROFILE"
	applicationAuthorityRelease             = "APPLICATION_RELEASE"
)

type ApplicationReleaseCreateRequest struct {
	ProjectID              string   `json:"projectId"`
	Name                   string   `json:"name"`
	Version                string   `json:"version"`
	WorkloadTypeID         string   `json:"workloadTypeId"`
	TraitIDs               []string `json:"traitIds,omitempty"`
	ManagedResourceTypeIDs []string `json:"managedResourceTypeIds,omitempty"`
	WorkspaceProfileID     string   `json:"workspaceProfileId"`
	SourceDigest           string   `json:"sourceDigest"`
}

type EnvironmentBindingCreateRequest struct {
	ReleaseID                  string   `json:"releaseId"`
	WorkspaceBindingID         string   `json:"workspaceBindingId"`
	Environment                string   `json:"environment"`
	ObservedNativeCapabilities []string `json:"observedNativeCapabilities,omitempty"`
}

type EnvironmentBindingPromotionRequest struct {
	ReleaseID                  string   `json:"releaseId"`
	ObservedNativeCapabilities []string `json:"observedNativeCapabilities,omitempty"`
}

func cloneWorkloadType(v WorkloadType) WorkloadType {
	v.AllowedTraitKinds = append([]string(nil), v.AllowedTraitKinds...)
	return v
}
func cloneManagedResourceType(v ManagedResourceType) ManagedResourceType {
	v.Outputs = append([]ManagedResourceOutput(nil), v.Outputs...)
	v.ReadinessConditions = append([]string(nil), v.ReadinessConditions...)
	return v
}
func cloneWorkspaceProfile(v WorkspaceProfile) WorkspaceProfile {
	v.AuthorityRefs = append([]ApplicationAuthorityRef(nil), v.AuthorityRefs...)
	return v
}
func cloneApplicationRelease(v ApplicationRelease) ApplicationRelease {
	v.TraitDigests = append([]string(nil), v.TraitDigests...)
	v.ManagedResourceDigests = append([]string(nil), v.ManagedResourceDigests...)
	return v
}

func sortApplicationNamed[T any](items []T, key func(T) (string, string, string)) {
	sort.Slice(items, func(i, j int) bool {
		in, iv, ii := key(items[i])
		jn, jv, ji := key(items[j])
		if in != jn { return in < jn }
		if iv != jv { return iv < jv }
		return ii < ji
	})
}

func (s *MemoryStore) CreateWorkloadType(_ context.Context, v WorkloadType, actor string) (WorkloadType, error) {
	s.mu.Lock(); defer s.mu.Unlock()
	if _, ok := s.projects[strings.TrimSpace(v.ProjectID)]; !ok { return WorkloadType{}, ErrNotFound }
	var err error
	v, err = NormalizeWorkloadType(v); if err != nil { return WorkloadType{}, err }
	for _, x := range s.workloadTypes { if x.ProjectID==v.ProjectID && x.Name==v.Name && x.Version==v.Version { return WorkloadType{}, ErrDuplicateName } }
	now:=nowUTC(s.now); v.ResourceMeta=ResourceMeta{ID:s.id("awt"),Revision:1,CreatedAt:now,UpdatedAt:now}
	s.workloadTypes[v.ID]=cloneWorkloadType(v)
	s.appendAuditLocked(actor,"application_workload_type.created","workloadType",v.ID,v.Revision,map[string]any{"projectId":v.ProjectID,"digest":v.Digest})
	s.appendOutboxLocked("workloadType",v.ID,"application_workload_type.created",v)
	return cloneWorkloadType(v),nil
}
func (s *MemoryStore) GetWorkloadType(_ context.Context,id string)(WorkloadType,error){s.mu.RLock();defer s.mu.RUnlock();v,ok:=s.workloadTypes[strings.TrimSpace(id)];if !ok{return WorkloadType{},ErrNotFound};return cloneWorkloadType(v),nil}
func (s *MemoryStore) ListWorkloadTypes(_ context.Context,projectID string)([]WorkloadType,error){s.mu.RLock();defer s.mu.RUnlock();projectID=strings.TrimSpace(projectID);out:=[]WorkloadType{};for _,v:=range s.workloadTypes{if projectID==""||v.ProjectID==projectID{out=append(out,cloneWorkloadType(v))}};sortApplicationNamed(out,func(v WorkloadType)(string,string,string){return v.Name,v.Version,v.ID});return out,nil}

func (s *MemoryStore) CreateCapabilityTrait(_ context.Context,v CapabilityTrait,actor string)(CapabilityTrait,error){
	s.mu.Lock();defer s.mu.Unlock()
	if _,ok:=s.projects[strings.TrimSpace(v.ProjectID)];!ok{return CapabilityTrait{},ErrNotFound}
	var err error;v,err=NormalizeCapabilityTrait(v);if err!=nil{return CapabilityTrait{},err}
	for _,x:=range s.capabilityTraits{if x.ProjectID==v.ProjectID&&x.Name==v.Name&&x.Version==v.Version{return CapabilityTrait{},ErrDuplicateName}}
	now:=nowUTC(s.now);v.ResourceMeta=ResourceMeta{ID:s.id("act"),Revision:1,CreatedAt:now,UpdatedAt:now};s.capabilityTraits[v.ID]=v
	s.appendAuditLocked(actor,"application_capability_trait.created","capabilityTrait",v.ID,v.Revision,map[string]any{"projectId":v.ProjectID,"capability":v.Capability,"digest":v.Digest});s.appendOutboxLocked("capabilityTrait",v.ID,"application_capability_trait.created",v);return v,nil
}
func(s *MemoryStore)GetCapabilityTrait(_ context.Context,id string)(CapabilityTrait,error){s.mu.RLock();defer s.mu.RUnlock();v,ok:=s.capabilityTraits[strings.TrimSpace(id)];if !ok{return CapabilityTrait{},ErrNotFound};return v,nil}
func(s *MemoryStore)ListCapabilityTraits(_ context.Context,projectID string)([]CapabilityTrait,error){s.mu.RLock();defer s.mu.RUnlock();projectID=strings.TrimSpace(projectID);out:=[]CapabilityTrait{};for _,v:=range s.capabilityTraits{if projectID==""||v.ProjectID==projectID{out=append(out,v)}};sortApplicationNamed(out,func(v CapabilityTrait)(string,string,string){return v.Name,v.Version,v.ID});return out,nil}

func(s *MemoryStore)CreateManagedResourceType(_ context.Context,v ManagedResourceType,actor string)(ManagedResourceType,error){
	s.mu.Lock();defer s.mu.Unlock();if _,ok:=s.projects[strings.TrimSpace(v.ProjectID)];!ok{return ManagedResourceType{},ErrNotFound}
	var err error;v,err=NormalizeManagedResourceType(v);if err!=nil{return ManagedResourceType{},err}
	for _,x:=range s.managedResourceTypes{if x.ProjectID==v.ProjectID&&x.Name==v.Name&&x.Version==v.Version{return ManagedResourceType{},ErrDuplicateName}}
	now:=nowUTC(s.now);v.ResourceMeta=ResourceMeta{ID:s.id("amr"),Revision:1,CreatedAt:now,UpdatedAt:now};s.managedResourceTypes[v.ID]=cloneManagedResourceType(v)
	s.appendAuditLocked(actor,"application_resource_type.created","managedResourceType",v.ID,v.Revision,map[string]any{"projectId":v.ProjectID,"category":v.Category,"digest":v.Digest});s.appendOutboxLocked("managedResourceType",v.ID,"application_resource_type.created",v);return cloneManagedResourceType(v),nil
}
func(s *MemoryStore)GetManagedResourceType(_ context.Context,id string)(ManagedResourceType,error){s.mu.RLock();defer s.mu.RUnlock();v,ok:=s.managedResourceTypes[strings.TrimSpace(id)];if !ok{return ManagedResourceType{},ErrNotFound};return cloneManagedResourceType(v),nil}
func(s *MemoryStore)ListManagedResourceTypes(_ context.Context,projectID string)([]ManagedResourceType,error){s.mu.RLock();defer s.mu.RUnlock();projectID=strings.TrimSpace(projectID);out:=[]ManagedResourceType{};for _,v:=range s.managedResourceTypes{if projectID==""||v.ProjectID==projectID{out=append(out,cloneManagedResourceType(v))}};sortApplicationNamed(out,func(v ManagedResourceType)(string,string,string){return v.Name,v.Version,v.ID});return out,nil}

func(s *MemoryStore)CreateWorkspaceProfile(_ context.Context,v WorkspaceProfile,actor string)(WorkspaceProfile,error){
	s.mu.Lock();defer s.mu.Unlock();if _,ok:=s.projects[strings.TrimSpace(v.ProjectID)];!ok{return WorkspaceProfile{},ErrNotFound}
	var err error;v,err=NormalizeWorkspaceProfile(v);if err!=nil{return WorkspaceProfile{},err}
	for _,ref:=range v.AuthorityRefs{if ref.Kind=="policy-set"{p,ok:=s.platformPolicySets[ref.ID];if !ok||p.ProjectID!=v.ProjectID||p.Digest!=ref.Digest{return WorkspaceProfile{},fmt.Errorf("%w: workspace profile policy-set reference is stale or cross-project",ErrValidation)}}}
	for _,x:=range s.workspaceProfiles{if x.ProjectID==v.ProjectID&&x.Name==v.Name&&x.Version==v.Version{return WorkspaceProfile{},ErrDuplicateName}}
	now:=nowUTC(s.now);v.ResourceMeta=ResourceMeta{ID:s.id("awp"),Revision:1,CreatedAt:now,UpdatedAt:now};s.workspaceProfiles[v.ID]=cloneWorkspaceProfile(v)
	s.appendAuditLocked(actor,"application_workspace_profile.created","workspaceProfile",v.ID,v.Revision,map[string]any{"projectId":v.ProjectID,"digest":v.Digest});s.appendOutboxLocked("workspaceProfile",v.ID,"application_workspace_profile.created",v);return cloneWorkspaceProfile(v),nil
}
func(s *MemoryStore)GetWorkspaceProfile(_ context.Context,id string)(WorkspaceProfile,error){s.mu.RLock();defer s.mu.RUnlock();v,ok:=s.workspaceProfiles[strings.TrimSpace(id)];if !ok{return WorkspaceProfile{},ErrNotFound};return cloneWorkspaceProfile(v),nil}
func(s *MemoryStore)ListWorkspaceProfiles(_ context.Context,projectID string)([]WorkspaceProfile,error){s.mu.RLock();defer s.mu.RUnlock();projectID=strings.TrimSpace(projectID);out:=[]WorkspaceProfile{};for _,v:=range s.workspaceProfiles{if projectID==""||v.ProjectID==projectID{out=append(out,cloneWorkspaceProfile(v))}};sortApplicationNamed(out,func(v WorkspaceProfile)(string,string,string){return v.Name,v.Version,v.ID});return out,nil}

func findWorkloadByDigest(m map[string]WorkloadType, projectID,digest string)(WorkloadType,bool){for _,v:=range m{if v.ProjectID==projectID&&v.Digest==digest{return v,true}};return WorkloadType{},false}
func findTraitByDigest(m map[string]CapabilityTrait, projectID,digest string)(CapabilityTrait,bool){for _,v:=range m{if v.ProjectID==projectID&&v.Digest==digest{return v,true}};return CapabilityTrait{},false}
func findResourceByDigest(m map[string]ManagedResourceType, projectID,digest string)(ManagedResourceType,bool){for _,v:=range m{if v.ProjectID==projectID&&v.Digest==digest{return v,true}};return ManagedResourceType{},false}
func findProfileByDigest(m map[string]WorkspaceProfile, projectID,digest string)(WorkspaceProfile,bool){for _,v:=range m{if v.ProjectID==projectID&&v.Digest==digest{return v,true}};return WorkspaceProfile{},false}

func(s *MemoryStore)CreateApplicationRelease(_ context.Context,req ApplicationReleaseCreateRequest,actor string)(ApplicationRelease,error){
	s.mu.Lock();defer s.mu.Unlock();req.ProjectID=strings.TrimSpace(req.ProjectID);if _,ok:=s.projects[req.ProjectID];!ok{return ApplicationRelease{},ErrNotFound}
	wt,ok:=s.workloadTypes[strings.TrimSpace(req.WorkloadTypeID)];if !ok||wt.ProjectID!=req.ProjectID{return ApplicationRelease{},ErrNotFound}
	profile,ok:=s.workspaceProfiles[strings.TrimSpace(req.WorkspaceProfileID)];if !ok||profile.ProjectID!=req.ProjectID{return ApplicationRelease{},ErrNotFound}
	traits:=make([]string,0,len(req.TraitIDs));for _,id:=range req.TraitIDs{v,ok:=s.capabilityTraits[strings.TrimSpace(id)];if !ok||v.ProjectID!=req.ProjectID{return ApplicationRelease{},ErrNotFound};traits=append(traits,v.Digest)}
	resources:=make([]string,0,len(req.ManagedResourceTypeIDs));for _,id:=range req.ManagedResourceTypeIDs{v,ok:=s.managedResourceTypes[strings.TrimSpace(id)];if !ok||v.ProjectID!=req.ProjectID{return ApplicationRelease{},ErrNotFound};resources=append(resources,v.Digest)}
	v,err:=NormalizeApplicationRelease(ApplicationRelease{ProjectID:req.ProjectID,Name:req.Name,Version:req.Version,WorkloadTypeDigest:wt.Digest,TraitDigests:traits,ManagedResourceDigests:resources,WorkspaceProfileDigest:profile.Digest,SourceDigest:req.SourceDigest});if err!=nil{return ApplicationRelease{},err}
	for _,x:=range s.applicationReleases{if x.ProjectID==v.ProjectID&&x.Name==v.Name&&x.Version==v.Version{return ApplicationRelease{},ErrDuplicateName}}
	now:=nowUTC(s.now);v.ResourceMeta=ResourceMeta{ID:s.id("arl"),Revision:1,CreatedAt:now,UpdatedAt:now};s.applicationReleases[v.ID]=cloneApplicationRelease(v)
	s.appendAuditLocked(actor,"application_release.created","applicationRelease",v.ID,v.Revision,map[string]any{"projectId":v.ProjectID,"digest":v.Digest});s.appendOutboxLocked("applicationRelease",v.ID,"application_release.created",v);return cloneApplicationRelease(v),nil
}
func(s *MemoryStore)GetApplicationRelease(_ context.Context,id string)(ApplicationRelease,error){s.mu.RLock();defer s.mu.RUnlock();v,ok:=s.applicationReleases[strings.TrimSpace(id)];if !ok{return ApplicationRelease{},ErrNotFound};return cloneApplicationRelease(v),nil}
func(s *MemoryStore)ListApplicationReleases(_ context.Context,projectID string)([]ApplicationRelease,error){s.mu.RLock();defer s.mu.RUnlock();projectID=strings.TrimSpace(projectID);out:=[]ApplicationRelease{};for _,v:=range s.applicationReleases{if projectID==""||v.ProjectID==projectID{out=append(out,cloneApplicationRelease(v))}};sortApplicationNamed(out,func(v ApplicationRelease)(string,string,string){return v.Name,v.Version,v.ID});return out,nil}

func resolveReleaseCompositionLocked(s *MemoryStore,release ApplicationRelease,observed []string)(WorkloadComposition,error){
	wt,ok:=findWorkloadByDigest(s.workloadTypes,release.ProjectID,release.WorkloadTypeDigest);if !ok{return WorkloadComposition{},fmt.Errorf("%w: release workload type digest is not present in project authority",ErrValidation)}
	traits:=make([]CapabilityTrait,0,len(release.TraitDigests));for _,digest:=range release.TraitDigests{v,ok:=findTraitByDigest(s.capabilityTraits,release.ProjectID,digest);if !ok{return WorkloadComposition{},fmt.Errorf("%w: release trait digest is not present in project authority",ErrValidation)};traits=append(traits,v)}
	return ResolveWorkloadComposition(wt,traits,observed)
}
func(s *MemoryStore)CreateEnvironmentBinding(_ context.Context,req EnvironmentBindingCreateRequest,actor string)(EnvironmentBinding,error){
	s.mu.Lock();defer s.mu.Unlock()
	release,ok:=s.applicationReleases[strings.TrimSpace(req.ReleaseID)];if !ok{return EnvironmentBinding{},ErrNotFound}
	wsb,ok:=s.workspaceBindings[strings.TrimSpace(req.WorkspaceBindingID)];if !ok{return EnvironmentBinding{},ErrNotFound}
	if wsb.State!=WorkspaceBindingActive||wsb.ProjectID!=release.ProjectID{return EnvironmentBinding{},fmt.Errorf("%w: environment binding requires an active same-project WorkspaceBinding",ErrValidation)}
	composition,err:=resolveReleaseCompositionLocked(s,release,req.ObservedNativeCapabilities);if err!=nil{return EnvironmentBinding{},err}
	v,err:=NormalizeEnvironmentBinding(EnvironmentBinding{ProjectID:release.ProjectID,ReleaseID:release.ID,ReleaseDigest:release.Digest,WorkspaceID:wsb.WorkspaceID,WorkspaceBindingID:wsb.ID,WorkspaceBindingRevision:wsb.Revision,ClusterID:wsb.ClusterID,Namespace:wsb.Namespace,Environment:req.Environment,CapabilityResolutionDigest:composition.ResolutionDigest});if err!=nil{return EnvironmentBinding{},err}
	for _,x:=range s.environmentBindings{if x.ProjectID==v.ProjectID&&x.WorkspaceBindingID==v.WorkspaceBindingID&&x.Environment==v.Environment{return EnvironmentBinding{},ErrDuplicateName}}
	now:=nowUTC(s.now);v.ResourceMeta=ResourceMeta{ID:s.id("aeb"),Revision:1,CreatedAt:now,UpdatedAt:now};s.environmentBindings[v.ID]=v
	s.appendAuditLocked(actor,"application_environment_binding.created","environmentBinding",v.ID,v.Revision,map[string]any{"projectId":v.ProjectID,"releaseId":v.ReleaseID,"workspaceBindingId":v.WorkspaceBindingID,"environment":v.Environment,"digest":v.Digest});s.appendOutboxLocked("environmentBinding",v.ID,"application_environment_binding.created",v);return v,nil
}
func(s *MemoryStore)PromoteEnvironmentBinding(_ context.Context,id string,expected int64,req EnvironmentBindingPromotionRequest,actor string)(EnvironmentBinding,error){
	s.mu.Lock();defer s.mu.Unlock();v,ok:=s.environmentBindings[strings.TrimSpace(id)];if !ok{return EnvironmentBinding{},ErrNotFound};if v.Revision!=expected{return EnvironmentBinding{},ErrConflict}
	wsb,ok:=s.workspaceBindings[v.WorkspaceBindingID];if !ok||wsb.State!=WorkspaceBindingActive||wsb.Revision!=v.WorkspaceBindingRevision||wsb.ProjectID!=v.ProjectID||wsb.ClusterID!=v.ClusterID||wsb.Namespace!=v.Namespace{return EnvironmentBinding{},fmt.Errorf("%w: environment binding WorkspaceBinding authority changed; rebind explicitly",ErrPrerequisite)}
	release,ok:=s.applicationReleases[strings.TrimSpace(req.ReleaseID)];if !ok||release.ProjectID!=v.ProjectID{return EnvironmentBinding{},ErrNotFound}
	composition,err:=resolveReleaseCompositionLocked(s,release,req.ObservedNativeCapabilities);if err!=nil{return EnvironmentBinding{},err}
	v.ReleaseID=release.ID;v.ReleaseDigest=release.Digest;v.CapabilityResolutionDigest=composition.ResolutionDigest;normalized,err:=NormalizeEnvironmentBinding(v);if err!=nil{return EnvironmentBinding{},err};normalized.ResourceMeta=v.ResourceMeta;normalized.Revision++;normalized.UpdatedAt=nowUTC(s.now);s.environmentBindings[id]=normalized
	s.appendAuditLocked(actor,"application_environment_binding.promoted","environmentBinding",id,normalized.Revision,map[string]any{"projectId":normalized.ProjectID,"releaseId":normalized.ReleaseID,"digest":normalized.Digest});s.appendOutboxLocked("environmentBinding",id,"application_environment_binding.promoted",normalized);return normalized,nil
}
func(s *MemoryStore)GetEnvironmentBinding(_ context.Context,id string)(EnvironmentBinding,error){s.mu.RLock();defer s.mu.RUnlock();v,ok:=s.environmentBindings[strings.TrimSpace(id)];if !ok{return EnvironmentBinding{},ErrNotFound};return v,nil}
func(s *MemoryStore)ListEnvironmentBindings(_ context.Context,projectID string)([]EnvironmentBinding,error){s.mu.RLock();defer s.mu.RUnlock();projectID=strings.TrimSpace(projectID);out:=[]EnvironmentBinding{};for _,v:=range s.environmentBindings{if projectID==""||v.ProjectID==projectID{out=append(out,v)}};sort.Slice(out,func(i,j int)bool{if out[i].Environment!=out[j].Environment{return out[i].Environment<out[j].Environment};if out[i].WorkspaceBindingID!=out[j].WorkspaceBindingID{return out[i].WorkspaceBindingID<out[j].WorkspaceBindingID};return out[i].ID<out[j].ID});return out,nil}

func validateApplicationPlatformSnapshot(snapshot Snapshot,projects map[string]Project,workspaces map[string]Workspace,clusters map[string]ManagedCluster) error {
	workloads:=map[string]WorkloadType{};workloadNames:=map[string]bool{}
	for _,v:=range snapshot.WorkloadTypes{n,err:=NormalizeWorkloadType(v);if err!=nil{return err};if _,ok:=projects[n.ProjectID];!ok{return fmt.Errorf("%w: workload type project missing",ErrValidation)};if v.Digest!=""&&v.Digest!=n.Digest{return fmt.Errorf("%w: workload type digest mismatch",ErrValidation)};key:=n.ProjectID+"\x00"+n.Name+"\x00"+n.Version;if workloadNames[key]{return fmt.Errorf("%w: duplicate workload type identity",ErrValidation)};workloadNames[key]=true;n.ResourceMeta=v.ResourceMeta;workloads[v.ID]=n}
	traits:=map[string]CapabilityTrait{};traitNames:=map[string]bool{}
	for _,v:=range snapshot.CapabilityTraits{n,err:=NormalizeCapabilityTrait(v);if err!=nil{return err};if _,ok:=projects[n.ProjectID];!ok{return fmt.Errorf("%w: capability trait project missing",ErrValidation)};if v.Digest!=""&&v.Digest!=n.Digest{return fmt.Errorf("%w: capability trait digest mismatch",ErrValidation)};key:=n.ProjectID+"\x00"+n.Name+"\x00"+n.Version;if traitNames[key]{return fmt.Errorf("%w: duplicate capability trait identity",ErrValidation)};traitNames[key]=true;n.ResourceMeta=v.ResourceMeta;traits[v.ID]=n}
	resources:=map[string]ManagedResourceType{};resourceNames:=map[string]bool{}
	for _,v:=range snapshot.ManagedResourceTypes{n,err:=NormalizeManagedResourceType(v);if err!=nil{return err};if _,ok:=projects[n.ProjectID];!ok{return fmt.Errorf("%w: managed resource type project missing",ErrValidation)};if v.Digest!=""&&v.Digest!=n.Digest{return fmt.Errorf("%w: managed resource type digest mismatch",ErrValidation)};key:=n.ProjectID+"\x00"+n.Name+"\x00"+n.Version;if resourceNames[key]{return fmt.Errorf("%w: duplicate managed resource type identity",ErrValidation)};resourceNames[key]=true;n.ResourceMeta=v.ResourceMeta;resources[v.ID]=n}
	profiles:=map[string]WorkspaceProfile{};profileNames:=map[string]bool{}
	for _,v:=range snapshot.WorkspaceProfiles{n,err:=NormalizeWorkspaceProfile(v);if err!=nil{return err};if _,ok:=projects[n.ProjectID];!ok{return fmt.Errorf("%w: workspace profile project missing",ErrValidation)};if v.Digest!=""&&v.Digest!=n.Digest{return fmt.Errorf("%w: workspace profile digest mismatch",ErrValidation)};key:=n.ProjectID+"\x00"+n.Name+"\x00"+n.Version;if profileNames[key]{return fmt.Errorf("%w: duplicate workspace profile identity",ErrValidation)};profileNames[key]=true;n.ResourceMeta=v.ResourceMeta;profiles[v.ID]=n}
	releases:=map[string]ApplicationRelease{};releaseNames:=map[string]bool{}
	for _,v:=range snapshot.ApplicationReleases{n,err:=NormalizeApplicationRelease(v);if err!=nil{return err};if _,ok:=projects[n.ProjectID];!ok{return fmt.Errorf("%w: application release project missing",ErrValidation)};if v.Digest!=""&&v.Digest!=n.Digest{return fmt.Errorf("%w: application release digest mismatch",ErrValidation)};if _,ok:=findWorkloadByDigest(workloads,n.ProjectID,n.WorkloadTypeDigest);!ok{return fmt.Errorf("%w: release workload digest is unresolved",ErrValidation)};for _,d:=range n.TraitDigests{if _,ok:=findTraitByDigest(traits,n.ProjectID,d);!ok{return fmt.Errorf("%w: release trait digest is unresolved",ErrValidation)}};for _,d:=range n.ManagedResourceDigests{if _,ok:=findResourceByDigest(resources,n.ProjectID,d);!ok{return fmt.Errorf("%w: release resource digest is unresolved",ErrValidation)}};if _,ok:=findProfileByDigest(profiles,n.ProjectID,n.WorkspaceProfileDigest);!ok{return fmt.Errorf("%w: release workspace profile digest is unresolved",ErrValidation)};key:=n.ProjectID+"\x00"+n.Name+"\x00"+n.Version;if releaseNames[key]{return fmt.Errorf("%w: duplicate application release identity",ErrValidation)};releaseNames[key]=true;n.ResourceMeta=v.ResourceMeta;releases[v.ID]=n}
	bindings:=map[string]WorkspaceBinding{};for _,b:=range snapshot.WorkspaceBindings{bindings[b.ID]=b}
	scope:=map[string]bool{}
	for _,v:=range snapshot.EnvironmentBindings{n,err:=NormalizeEnvironmentBinding(v);if err!=nil{return err};rel,ok:=releases[n.ReleaseID];if !ok||rel.ProjectID!=n.ProjectID||rel.Digest!=n.ReleaseDigest{return fmt.Errorf("%w: environment binding release authority mismatch",ErrValidation)};wsb,ok:=bindings[n.WorkspaceBindingID];if !ok||wsb.State!=WorkspaceBindingActive||wsb.Revision!=n.WorkspaceBindingRevision||wsb.ProjectID!=n.ProjectID||wsb.WorkspaceID!=n.WorkspaceID||wsb.ClusterID!=n.ClusterID||wsb.Namespace!=n.Namespace{return fmt.Errorf("%w: environment binding WorkspaceBinding authority mismatch",ErrValidation)};if _,ok:=workspaces[n.WorkspaceID];!ok{return fmt.Errorf("%w: environment binding workspace missing",ErrValidation)};if _,ok:=clusters[n.ClusterID];!ok{return fmt.Errorf("%w: environment binding cluster missing",ErrValidation)};if v.Digest!=""&&v.Digest!=n.Digest{return fmt.Errorf("%w: environment binding digest mismatch",ErrValidation)};key:=n.ProjectID+"\x00"+n.WorkspaceBindingID+"\x00"+n.Environment;if scope[key]{return fmt.Errorf("%w: duplicate environment binding scope",ErrValidation)};scope[key]=true}
	return nil
}
