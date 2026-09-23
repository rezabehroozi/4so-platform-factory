package persistence

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
)

const applicationEnvironmentBindingColumns = `id,project_id,revision,release_id,release_digest,workspace_id,workspace_binding_id,workspace_binding_revision,cluster_id,namespace,environment,capability_resolution_digest,digest,created_at,updated_at`

type applicationPayloadScanner interface{ Scan(...any) error }

func decodeApplicationAuthority[T any](scanner applicationPayloadScanner) (T,error) {
	var out T
	var raw []byte
	if err:=scanner.Scan(&raw);err!=nil{return out,mapDBError(err)}
	if err:=json.Unmarshal(raw,&out);err!=nil{return out,fmt.Errorf("decode application platform authority payload: %w",err)}
	return out,nil
}

func (s *PostgresStore) createApplicationAuthority(ctx context.Context,kind,resourceType,event string,projectID,name,version,digest string,payload any,actor string) error {
	raw,err:=json.Marshal(payload);if err!=nil{return err}
	return s.serializable(ctx,func(tx *sql.Tx)error{
		var project string
		if err:=tx.QueryRowContext(ctx,`SELECT id FROM projects WHERE id=$1 FOR SHARE`,projectID).Scan(&project);err!=nil{return mapDBError(err)}
		if _,err:=tx.ExecContext(ctx,`INSERT INTO application_platform_authorities(id,project_id,revision,kind,name,version,digest,payload,created_by,created_at,updated_at) VALUES($1,$2,1,$3,$4,$5,$6,$7::jsonb,$8,$9,$9)`,
			applicationAuthorityID(payload),projectID,kind,name,version,digest,raw,strings.TrimSpace(actor),applicationAuthorityTime(payload));err!=nil{return mapDBError(err)}
		if err:=s.appendAuditTx(ctx,tx,actor,event,resourceType,applicationAuthorityID(payload),1,"",map[string]any{"projectId":projectID,"digest":digest});err!=nil{return err}
		return s.appendOutboxTx(ctx,tx,resourceType,applicationAuthorityID(payload),event,payload)
	})
}

func applicationAuthorityID(v any) string {
	switch x:=v.(type){
	case controlplane.WorkloadType:return x.ID
	case controlplane.CapabilityTrait:return x.ID
	case controlplane.ManagedResourceType:return x.ID
	case controlplane.WorkspaceProfile:return x.ID
	case controlplane.ApplicationRelease:return x.ID
	default:return ""
	}
}
func applicationAuthorityTime(v any) any {
	switch x:=v.(type){
	case controlplane.WorkloadType:return x.CreatedAt
	case controlplane.CapabilityTrait:return x.CreatedAt
	case controlplane.ManagedResourceType:return x.CreatedAt
	case controlplane.WorkspaceProfile:return x.CreatedAt
	case controlplane.ApplicationRelease:return x.CreatedAt
	default:return nil
	}
}

func (s *PostgresStore) CreateWorkloadType(ctx context.Context,v controlplane.WorkloadType,actor string)(controlplane.WorkloadType,error){
	var err error;v,err=controlplane.NormalizeWorkloadType(v);if err!=nil{return v,err};now:=utcNow(s.now);v.ResourceMeta=controlplane.ResourceMeta{ID:s.id("awt"),Revision:1,CreatedAt:now,UpdatedAt:now}
	err=s.createApplicationAuthority(ctx,"WORKLOAD_TYPE","workloadType","application_workload_type.created",v.ProjectID,v.Name,v.Version,v.Digest,v,actor);return v,err
}
func(s *PostgresStore)GetWorkloadType(ctx context.Context,id string)(controlplane.WorkloadType,error){return decodeApplicationAuthority[controlplane.WorkloadType](s.db.QueryRowContext(ctx,`SELECT payload FROM application_platform_authorities WHERE id=$1 AND kind='WORKLOAD_TYPE'`,strings.TrimSpace(id)))}
func(s *PostgresStore)ListWorkloadTypes(ctx context.Context,projectID string)([]controlplane.WorkloadType,error){rows,err:=s.db.QueryContext(ctx,`SELECT payload FROM application_platform_authorities WHERE kind='WORKLOAD_TYPE' AND ($1='' OR project_id=$1) ORDER BY lower(name),version,id`,strings.TrimSpace(projectID));if err!=nil{return nil,err};defer rows.Close();out:=[]controlplane.WorkloadType{};for rows.Next(){v,e:=decodeApplicationAuthority[controlplane.WorkloadType](rows);if e!=nil{return nil,e};out=append(out,v)};return out,rows.Err()}

func(s *PostgresStore)CreateCapabilityTrait(ctx context.Context,v controlplane.CapabilityTrait,actor string)(controlplane.CapabilityTrait,error){var err error;v,err=controlplane.NormalizeCapabilityTrait(v);if err!=nil{return v,err};now:=utcNow(s.now);v.ResourceMeta=controlplane.ResourceMeta{ID:s.id("act"),Revision:1,CreatedAt:now,UpdatedAt:now};err=s.createApplicationAuthority(ctx,"CAPABILITY_TRAIT","capabilityTrait","application_capability_trait.created",v.ProjectID,v.Name,v.Version,v.Digest,v,actor);return v,err}
func(s *PostgresStore)GetCapabilityTrait(ctx context.Context,id string)(controlplane.CapabilityTrait,error){return decodeApplicationAuthority[controlplane.CapabilityTrait](s.db.QueryRowContext(ctx,`SELECT payload FROM application_platform_authorities WHERE id=$1 AND kind='CAPABILITY_TRAIT'`,strings.TrimSpace(id)))}
func(s *PostgresStore)ListCapabilityTraits(ctx context.Context,projectID string)([]controlplane.CapabilityTrait,error){rows,err:=s.db.QueryContext(ctx,`SELECT payload FROM application_platform_authorities WHERE kind='CAPABILITY_TRAIT' AND ($1='' OR project_id=$1) ORDER BY lower(name),version,id`,strings.TrimSpace(projectID));if err!=nil{return nil,err};defer rows.Close();out:=[]controlplane.CapabilityTrait{};for rows.Next(){v,e:=decodeApplicationAuthority[controlplane.CapabilityTrait](rows);if e!=nil{return nil,e};out=append(out,v)};return out,rows.Err()}

func(s *PostgresStore)CreateManagedResourceType(ctx context.Context,v controlplane.ManagedResourceType,actor string)(controlplane.ManagedResourceType,error){var err error;v,err=controlplane.NormalizeManagedResourceType(v);if err!=nil{return v,err};now:=utcNow(s.now);v.ResourceMeta=controlplane.ResourceMeta{ID:s.id("amr"),Revision:1,CreatedAt:now,UpdatedAt:now};err=s.createApplicationAuthority(ctx,"MANAGED_RESOURCE_TYPE","managedResourceType","application_resource_type.created",v.ProjectID,v.Name,v.Version,v.Digest,v,actor);return v,err}
func(s *PostgresStore)GetManagedResourceType(ctx context.Context,id string)(controlplane.ManagedResourceType,error){return decodeApplicationAuthority[controlplane.ManagedResourceType](s.db.QueryRowContext(ctx,`SELECT payload FROM application_platform_authorities WHERE id=$1 AND kind='MANAGED_RESOURCE_TYPE'`,strings.TrimSpace(id)))}
func(s *PostgresStore)ListManagedResourceTypes(ctx context.Context,projectID string)([]controlplane.ManagedResourceType,error){rows,err:=s.db.QueryContext(ctx,`SELECT payload FROM application_platform_authorities WHERE kind='MANAGED_RESOURCE_TYPE' AND ($1='' OR project_id=$1) ORDER BY lower(name),version,id`,strings.TrimSpace(projectID));if err!=nil{return nil,err};defer rows.Close();out:=[]controlplane.ManagedResourceType{};for rows.Next(){v,e:=decodeApplicationAuthority[controlplane.ManagedResourceType](rows);if e!=nil{return nil,e};out=append(out,v)};return out,rows.Err()}

func(s *PostgresStore)CreateWorkspaceProfile(ctx context.Context,v controlplane.WorkspaceProfile,actor string)(controlplane.WorkspaceProfile,error){
	var err error;v,err=controlplane.NormalizeWorkspaceProfile(v);if err!=nil{return v,err}
	for _,ref:=range v.AuthorityRefs{if ref.Kind=="policy-set"{p,e:=s.GetPlatformPolicySet(ctx,ref.ID);if e!=nil{return v,e};if p.ProjectID!=v.ProjectID||p.Digest!=ref.Digest{return v,fmt.Errorf("%w: workspace profile policy-set reference is stale or cross-project",controlplane.ErrValidation)}}}
	now:=utcNow(s.now);v.ResourceMeta=controlplane.ResourceMeta{ID:s.id("awp"),Revision:1,CreatedAt:now,UpdatedAt:now};err=s.createApplicationAuthority(ctx,"WORKSPACE_PROFILE","workspaceProfile","application_workspace_profile.created",v.ProjectID,v.Name,v.Version,v.Digest,v,actor);return v,err
}
func(s *PostgresStore)GetWorkspaceProfile(ctx context.Context,id string)(controlplane.WorkspaceProfile,error){return decodeApplicationAuthority[controlplane.WorkspaceProfile](s.db.QueryRowContext(ctx,`SELECT payload FROM application_platform_authorities WHERE id=$1 AND kind='WORKSPACE_PROFILE'`,strings.TrimSpace(id)))}
func(s *PostgresStore)ListWorkspaceProfiles(ctx context.Context,projectID string)([]controlplane.WorkspaceProfile,error){rows,err:=s.db.QueryContext(ctx,`SELECT payload FROM application_platform_authorities WHERE kind='WORKSPACE_PROFILE' AND ($1='' OR project_id=$1) ORDER BY lower(name),version,id`,strings.TrimSpace(projectID));if err!=nil{return nil,err};defer rows.Close();out:=[]controlplane.WorkspaceProfile{};for rows.Next(){v,e:=decodeApplicationAuthority[controlplane.WorkspaceProfile](rows);if e!=nil{return nil,e};out=append(out,v)};return out,rows.Err()}

func(s *PostgresStore)CreateApplicationRelease(ctx context.Context,req controlplane.ApplicationReleaseCreateRequest,actor string)(controlplane.ApplicationRelease,error){
	req.ProjectID=strings.TrimSpace(req.ProjectID);wt,err:=s.GetWorkloadType(ctx,req.WorkloadTypeID);if err!=nil{return controlplane.ApplicationRelease{},err};if wt.ProjectID!=req.ProjectID{return controlplane.ApplicationRelease{},controlplane.ErrNotFound}
	profile,err:=s.GetWorkspaceProfile(ctx,req.WorkspaceProfileID);if err!=nil{return controlplane.ApplicationRelease{},err};if profile.ProjectID!=req.ProjectID{return controlplane.ApplicationRelease{},controlplane.ErrNotFound}
	traits:=[]string{};for _,id:=range req.TraitIDs{v,e:=s.GetCapabilityTrait(ctx,id);if e!=nil{return controlplane.ApplicationRelease{},e};if v.ProjectID!=req.ProjectID{return controlplane.ApplicationRelease{},controlplane.ErrNotFound};traits=append(traits,v.Digest)}
	resources:=[]string{};for _,id:=range req.ManagedResourceTypeIDs{v,e:=s.GetManagedResourceType(ctx,id);if e!=nil{return controlplane.ApplicationRelease{},e};if v.ProjectID!=req.ProjectID{return controlplane.ApplicationRelease{},controlplane.ErrNotFound};resources=append(resources,v.Digest)}
	v,err:=controlplane.NormalizeApplicationRelease(controlplane.ApplicationRelease{ProjectID:req.ProjectID,Name:req.Name,Version:req.Version,WorkloadTypeDigest:wt.Digest,TraitDigests:traits,ManagedResourceDigests:resources,WorkspaceProfileDigest:profile.Digest,SourceDigest:req.SourceDigest});if err!=nil{return v,err}
	now:=utcNow(s.now);v.ResourceMeta=controlplane.ResourceMeta{ID:s.id("arl"),Revision:1,CreatedAt:now,UpdatedAt:now};err=s.createApplicationAuthority(ctx,"APPLICATION_RELEASE","applicationRelease","application_release.created",v.ProjectID,v.Name,v.Version,v.Digest,v,actor);return v,err
}
func(s *PostgresStore)GetApplicationRelease(ctx context.Context,id string)(controlplane.ApplicationRelease,error){return decodeApplicationAuthority[controlplane.ApplicationRelease](s.db.QueryRowContext(ctx,`SELECT payload FROM application_platform_authorities WHERE id=$1 AND kind='APPLICATION_RELEASE'`,strings.TrimSpace(id)))}
func(s *PostgresStore)ListApplicationReleases(ctx context.Context,projectID string)([]controlplane.ApplicationRelease,error){rows,err:=s.db.QueryContext(ctx,`SELECT payload FROM application_platform_authorities WHERE kind='APPLICATION_RELEASE' AND ($1='' OR project_id=$1) ORDER BY lower(name),version,id`,strings.TrimSpace(projectID));if err!=nil{return nil,err};defer rows.Close();out:=[]controlplane.ApplicationRelease{};for rows.Next(){v,e:=decodeApplicationAuthority[controlplane.ApplicationRelease](rows);if e!=nil{return nil,e};out=append(out,v)};return out,rows.Err()}

func(s *PostgresStore)resolveApplicationRelease(ctx context.Context,release controlplane.ApplicationRelease,observed []string)(controlplane.WorkloadComposition,error){
	workloads,err:=s.ListWorkloadTypes(ctx,release.ProjectID);if err!=nil{return controlplane.WorkloadComposition{},err};var wt controlplane.WorkloadType;found:=false;for _,v:=range workloads{if v.Digest==release.WorkloadTypeDigest{wt=v;found=true;break}};if !found{return controlplane.WorkloadComposition{},fmt.Errorf("%w: release workload digest is unresolved",controlplane.ErrValidation)}
	allTraits,err:=s.ListCapabilityTraits(ctx,release.ProjectID);if err!=nil{return controlplane.WorkloadComposition{},err};traits:=[]controlplane.CapabilityTrait{};for _,digest:=range release.TraitDigests{ok:=false;for _,v:=range allTraits{if v.Digest==digest{traits=append(traits,v);ok=true;break}};if !ok{return controlplane.WorkloadComposition{},fmt.Errorf("%w: release trait digest is unresolved",controlplane.ErrValidation)}}
	return controlplane.ResolveWorkloadComposition(wt,traits,observed)
}
func scanEnvironmentBinding(scanner applicationPayloadScanner)(controlplane.EnvironmentBinding,error){var v controlplane.EnvironmentBinding;err:=scanner.Scan(&v.ID,&v.ProjectID,&v.Revision,&v.ReleaseID,&v.ReleaseDigest,&v.WorkspaceID,&v.WorkspaceBindingID,&v.WorkspaceBindingRevision,&v.ClusterID,&v.Namespace,&v.Environment,&v.CapabilityResolutionDigest,&v.Digest,&v.CreatedAt,&v.UpdatedAt);return v,mapDBError(err)}
func(s *PostgresStore)CreateEnvironmentBinding(ctx context.Context,req controlplane.EnvironmentBindingCreateRequest,actor string)(controlplane.EnvironmentBinding,error){
	release,err:=s.GetApplicationRelease(ctx,req.ReleaseID);if err!=nil{return controlplane.EnvironmentBinding{},err};wsb,err:=s.GetWorkspaceBinding(ctx,req.WorkspaceBindingID);if err!=nil{return controlplane.EnvironmentBinding{},err};if wsb.State!=controlplane.WorkspaceBindingActive||wsb.ProjectID!=release.ProjectID{return controlplane.EnvironmentBinding{},fmt.Errorf("%w: environment binding requires an active same-project WorkspaceBinding",controlplane.ErrValidation)}
	comp,err:=s.resolveApplicationRelease(ctx,release,req.ObservedNativeCapabilities);if err!=nil{return controlplane.EnvironmentBinding{},err}
	v,err:=controlplane.NormalizeEnvironmentBinding(controlplane.EnvironmentBinding{ProjectID:release.ProjectID,ReleaseID:release.ID,ReleaseDigest:release.Digest,WorkspaceID:wsb.WorkspaceID,WorkspaceBindingID:wsb.ID,WorkspaceBindingRevision:wsb.Revision,ClusterID:wsb.ClusterID,Namespace:wsb.Namespace,Environment:req.Environment,CapabilityResolutionDigest:comp.ResolutionDigest});if err!=nil{return v,err}
	now:=utcNow(s.now);v.ResourceMeta=controlplane.ResourceMeta{ID:s.id("aeb"),Revision:1,CreatedAt:now,UpdatedAt:now}
	err=s.serializable(ctx,func(tx *sql.Tx)error{if _,e:=tx.ExecContext(ctx,`INSERT INTO application_environment_bindings(id,project_id,revision,release_id,release_digest,workspace_id,workspace_binding_id,workspace_binding_revision,cluster_id,namespace,environment,capability_resolution_digest,digest,created_by,created_at,updated_at) VALUES($1,$2,1,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$14)`,v.ID,v.ProjectID,v.ReleaseID,v.ReleaseDigest,v.WorkspaceID,v.WorkspaceBindingID,v.WorkspaceBindingRevision,v.ClusterID,v.Namespace,v.Environment,v.CapabilityResolutionDigest,v.Digest,strings.TrimSpace(actor),now);e!=nil{return mapDBError(e)};if e:=s.appendAuditTx(ctx,tx,actor,"application_environment_binding.created","environmentBinding",v.ID,1,"",map[string]any{"projectId":v.ProjectID,"releaseId":v.ReleaseID,"workspaceBindingId":v.WorkspaceBindingID,"environment":v.Environment,"digest":v.Digest});e!=nil{return e};return s.appendOutboxTx(ctx,tx,"environmentBinding",v.ID,"application_environment_binding.created",v)})
	return v,err
}
func(s *PostgresStore)GetEnvironmentBinding(ctx context.Context,id string)(controlplane.EnvironmentBinding,error){return scanEnvironmentBinding(s.db.QueryRowContext(ctx,`SELECT `+applicationEnvironmentBindingColumns+` FROM application_environment_bindings WHERE id=$1`,strings.TrimSpace(id)))}
func(s *PostgresStore)ListEnvironmentBindings(ctx context.Context,projectID string)([]controlplane.EnvironmentBinding,error){rows,err:=s.db.QueryContext(ctx,`SELECT `+applicationEnvironmentBindingColumns+` FROM application_environment_bindings WHERE ($1='' OR project_id=$1) ORDER BY environment,workspace_binding_id,id`,strings.TrimSpace(projectID));if err!=nil{return nil,err};defer rows.Close();out:=[]controlplane.EnvironmentBinding{};for rows.Next(){v,e:=scanEnvironmentBinding(rows);if e!=nil{return nil,e};out=append(out,v)};return out,rows.Err()}
func(s *PostgresStore)PromoteEnvironmentBinding(ctx context.Context,id string,expected int64,req controlplane.EnvironmentBindingPromotionRequest,actor string)(controlplane.EnvironmentBinding,error){
	current,err:=s.GetEnvironmentBinding(ctx,id);if err!=nil{return current,err};if current.Revision!=expected{return current,controlplane.ErrConflict}
	wsb,err:=s.GetWorkspaceBinding(ctx,current.WorkspaceBindingID);if err!=nil{return current,err};if wsb.State!=controlplane.WorkspaceBindingActive||wsb.Revision!=current.WorkspaceBindingRevision||wsb.ProjectID!=current.ProjectID||wsb.ClusterID!=current.ClusterID||wsb.Namespace!=current.Namespace{return current,fmt.Errorf("%w: environment binding WorkspaceBinding authority changed; rebind explicitly",controlplane.ErrPrerequisite)}
	release,err:=s.GetApplicationRelease(ctx,req.ReleaseID);if err!=nil{return current,err};if release.ProjectID!=current.ProjectID{return current,controlplane.ErrNotFound};comp,err:=s.resolveApplicationRelease(ctx,release,req.ObservedNativeCapabilities);if err!=nil{return current,err}
	current.ReleaseID=release.ID;current.ReleaseDigest=release.Digest;current.CapabilityResolutionDigest=comp.ResolutionDigest;normalized,err:=controlplane.NormalizeEnvironmentBinding(current);if err!=nil{return current,err};normalized.ResourceMeta=current.ResourceMeta;normalized.Revision=current.Revision+1;normalized.UpdatedAt=utcNow(s.now)
	err=s.serializable(ctx,func(tx *sql.Tx)error{result,e:=tx.ExecContext(ctx,`UPDATE application_environment_bindings SET revision=$2,release_id=$3,release_digest=$4,capability_resolution_digest=$5,digest=$6,updated_at=$7 WHERE id=$1 AND revision=$8`,normalized.ID,normalized.Revision,normalized.ReleaseID,normalized.ReleaseDigest,normalized.CapabilityResolutionDigest,normalized.Digest,normalized.UpdatedAt,expected);if e!=nil{return mapDBError(e)};n,_:=result.RowsAffected();if n!=1{return controlplane.ErrConflict};if e=s.appendAuditTx(ctx,tx,actor,"application_environment_binding.promoted","environmentBinding",normalized.ID,normalized.Revision,"",map[string]any{"projectId":normalized.ProjectID,"releaseId":normalized.ReleaseID,"digest":normalized.Digest});e!=nil{return e};return s.appendOutboxTx(ctx,tx,"environmentBinding",normalized.ID,"application_environment_binding.promoted",normalized)})
	return normalized,err
}

var _ = errors.Is
