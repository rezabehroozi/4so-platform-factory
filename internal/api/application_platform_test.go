package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/auth"
	"platform.4so.io/factory/internal/controlplane"
)

func applicationPlatformRequest(t *testing.T,s *Server,method,path,body,subject string,headers map[string]string)*httptest.ResponseRecorder{
	t.Helper();req:=httptest.NewRequest(method,path,bytes.NewBufferString(body));if body!=""{req.Header.Set("Content-Type","application/json")};for k,v:=range headers{req.Header.Set(k,v)}
	req=req.WithContext(auth.WithPrincipal(req.Context(),auth.Principal{Subject:subject,Roles:[]string{"platform-operator"},Expires:time.Now().Add(time.Hour).Unix()}));w:=httptest.NewRecorder();s.Handler().ServeHTTP(w,req);return w
}
func decodeApplicationResponse[T any](t *testing.T,w *httptest.ResponseRecorder)T{t.Helper();var v T;if err:=json.Unmarshal(w.Body.Bytes(),&v);err!=nil{t.Fatalf("decode %d %s: %v",w.Code,w.Body.String(),err)};return v}

func TestApplicationPlatformHTTPReleaseBindingPromotionAndRevocationFence(t *testing.T){
	store:=controlplane.NewMemoryStore();ctx:=context.Background()
	org,_:=store.CreateOrganization(ctx,controlplane.Organization{Name:"app-platform",DisplayName:"Application Platform"},"owner")
	project,_:=store.CreateProject(ctx,controlplane.Project{OrganizationID:org.ID,Name:"payments",DisplayName:"Payments"},"owner")
	policy,err:=store.CreatePlatformPolicySet(ctx,controlplane.PlatformPolicySet{ProjectID:project.ID,Name:"production",Version:"1.0.0",Maintenance:controlplane.PlatformMaintenancePolicy{RiskClass:"PRODUCTION",RequireApproval:true,MaxUnavailable:1,RequireRecoveryCheckpoint:true},Backup:controlplane.PlatformBackupPolicy{Required:true,Provider:"s3",Schedule:"0 2 * * *",Retention:"30d"},Security:controlplane.PlatformSecurityPolicy{PodSecurityLevel:"restricted",DefaultDenyIngress:true,DefaultDenyEgress:true,AllowDNS:true}},"owner");if err!=nil{t.Fatal(err)}
	cluster:=workspaceAPICluster(t,store,project.ID,"app-host","uid-app-platform")
	workspace,_:=store.CreateWorkspace(ctx,controlplane.Workspace{ProjectID:project.ID,Name:"payments",DisplayName:"Payments"},"owner")
	wsb,_:=store.CreateWorkspaceBinding(ctx,controlplane.WorkspaceBinding{WorkspaceID:workspace.ID,ClusterID:cluster.ID,Namespace:"payments"},"owner")
	srv:=scopedServer(t,store);digest:=func(ch string)string{return "sha256:"+strings.Repeat(ch,64)}

	w:=applicationPlatformRequest(t,srv,http.MethodPost,"/api/v1/application-platform/workload-types",fmt.Sprintf(`{"projectId":%q,"name":"service","version":"1.0.0","inputSchemaDigest":%q,"allowedTraitKinds":["ingress","security"]}`,project.ID,digest("a")),"owner",nil);if w.Code!=201{t.Fatalf("workload=%d %s",w.Code,w.Body.String())};wt:=decodeApplicationResponse[controlplane.WorkloadType](t,w)
	w=applicationPlatformRequest(t,srv,http.MethodPost,"/api/v1/application-platform/capability-traits",fmt.Sprintf(`{"projectId":%q,"name":"ingress","version":"1.0.0","kind":"ingress","capability":"networking.ingress","inputSchemaDigest":%q,"nativeSuppression":true}`,project.ID,digest("b")),"owner",nil);if w.Code!=201{t.Fatalf("trait=%d %s",w.Code,w.Body.String())};trait:=decodeApplicationResponse[controlplane.CapabilityTrait](t,w)
	w=applicationPlatformRequest(t,srv,http.MethodPost,"/api/v1/application-platform/resource-types",fmt.Sprintf(`{"projectId":%q,"name":"postgres","version":"1.0.0","category":"database","provisioner":"product-api","inputSchemaDigest":%q,"outputs":[{"name":"endpoint","type":"endpoint"},{"name":"credentials","type":"secret-reference","sensitive":true,"secretReference":true}],"deletePolicy":"retain","retentionPolicy":"customer-data","readinessConditions":["endpoint-ready","credentials-ready"]}`,project.ID,digest("c")),"owner",nil);if w.Code!=201{t.Fatalf("resource=%d %s",w.Code,w.Body.String())};resource:=decodeApplicationResponse[controlplane.ManagedResourceType](t,w)
	w=applicationPlatformRequest(t,srv,http.MethodPost,"/api/v1/application-platform/workspace-profiles",fmt.Sprintf(`{"projectId":%q,"name":"production","version":"1.0.0","authorityRefs":[{"kind":"policy-set","id":%q,"digest":%q}]}`,project.ID,policy.ID,policy.Digest),"owner",nil);if w.Code!=201{t.Fatalf("profile=%d %s",w.Code,w.Body.String())};profile:=decodeApplicationResponse[controlplane.WorkspaceProfile](t,w)
	w=applicationPlatformRequest(t,srv,http.MethodPost,"/api/v1/application-platform/resolve",fmt.Sprintf(`{"projectId":%q,"workloadTypeId":%q,"traitIds":[%q],"observedNativeCapabilities":["networking.ingress"]}`,project.ID,wt.ID,trait.ID),"owner",nil);if w.Code!=200{t.Fatalf("resolve=%d %s",w.Code,w.Body.String())};composition:=decodeApplicationResponse[controlplane.WorkloadComposition](t,w);if len(composition.Decisions)!=1||composition.Decisions[0].Action!=controlplane.TraitDecisionSuppressNative{t.Fatalf("composition=%#v",composition)}
	createRelease:=func(version,source string)controlplane.ApplicationRelease{body:=fmt.Sprintf(`{"projectId":%q,"name":"payments","version":%q,"workloadTypeId":%q,"traitIds":[%q],"managedResourceTypeIds":[%q],"workspaceProfileId":%q,"sourceDigest":%q}`,project.ID,version,wt.ID,trait.ID,resource.ID,profile.ID,source);rw:=applicationPlatformRequest(t,srv,http.MethodPost,"/api/v1/application-platform/releases",body,"owner",nil);if rw.Code!=201{t.Fatalf("release=%d %s",rw.Code,rw.Body.String())};return decodeApplicationResponse[controlplane.ApplicationRelease](t,rw)}
	r1:=createRelease("1.0.0",digest("d"));r2:=createRelease("1.1.0",digest("e"))
	w=applicationPlatformRequest(t,srv,http.MethodPost,"/api/v1/application-platform/environment-bindings",fmt.Sprintf(`{"releaseId":%q,"workspaceBindingId":%q,"environment":"production","observedNativeCapabilities":["networking.ingress"]}`,r1.ID,wsb.ID),"owner",nil);if w.Code!=201{t.Fatalf("binding=%d %s",w.Code,w.Body.String())};binding:=decodeApplicationResponse[controlplane.EnvironmentBinding](t,w);if binding.WorkspaceBindingRevision!=wsb.Revision||binding.ReleaseDigest!=r1.Digest{t.Fatalf("binding authority=%#v",binding)}
	w=applicationPlatformRequest(t,srv,http.MethodPost,"/api/v1/application-platform/environment-bindings/"+binding.ID+"/promote",fmt.Sprintf(`{"releaseId":%q,"observedNativeCapabilities":["networking.ingress"]}`,r2.ID),"owner",map[string]string{"If-Match":"\"1\""});if w.Code!=200{t.Fatalf("promote=%d %s",w.Code,w.Body.String())};promoted:=decodeApplicationResponse[controlplane.EnvironmentBinding](t,w);if promoted.Revision!=2||promoted.ReleaseID!=r2.ID||promoted.Digest==binding.Digest{t.Fatalf("promotion=%#v",promoted)}
	if _,err=store.RevokeWorkspaceBinding(ctx,wsb.ID,wsb.Revision,"owner");err!=nil{t.Fatal(err)}
	w=applicationPlatformRequest(t,srv,http.MethodPost,"/api/v1/application-platform/environment-bindings/"+binding.ID+"/promote",fmt.Sprintf(`{"releaseId":%q}`,r1.ID),"owner",map[string]string{"If-Match":"\"2\""});if w.Code<400{t.Fatalf("revoked WorkspaceBinding promotion unexpectedly succeeded: %d %s",w.Code,w.Body.String())}
}
