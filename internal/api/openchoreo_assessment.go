package api

import (
	"net/http"
	"strings"
	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/targetmodel"
)
type openChoreoAssessmentInput struct{ProjectID string `json:"projectId"`;ClusterID string `json:"clusterId"`;Disconnected bool `json:"disconnected"`}
func (s *Server) assessOpenChoreoTargetAdapter(w http.ResponseWriter,r *http.Request){
	var input openChoreoAssessmentInput;if err:=decodeJSON(w,r,&input);err!=nil{return};input.ProjectID=strings.TrimSpace(input.ProjectID);input.ClusterID=strings.TrimSpace(input.ClusterID)
	if input.ProjectID==""||input.ClusterID==""{writeError(w,http.StatusUnprocessableEntity,"TARGET_SCOPE_REQUIRED","projectId and clusterId are required");return}
	if _,err:=s.requireProjectAccess(r,input.ProjectID,organizationRead);err!=nil{writeScopeError(w,err);return}
	cluster,err:=s.store.GetManagedCluster(r.Context(),input.ClusterID);if err!=nil||cluster.ProjectID!=input.ProjectID{writeStoreError(w,controlplane.ErrNotFound);return}
	inv,err:=s.store.GetLatestClusterInventory(r.Context(),cluster.ID);if err!=nil{
		out:=targetmodel.EvaluateOpenChoreoTargetAdapterAdmission(targetmodel.OpenChoreoTargetAdapterAdmissionInput{DistributionIdentity:cluster.Distribution,TargetAdmitted:cluster.ConnectionState!="REVOKED",Disconnected:input.Disconnected});writeJSON(w,http.StatusOK,out);return}
	complete:=inv.APIDiscoveryComplete&&inv.CRDDiscoveryComplete&&inv.SchemaDiscoveryComplete
	out:=targetmodel.EvaluateOpenChoreoTargetAdapterAdmission(targetmodel.OpenChoreoTargetAdapterAdmissionInput{DistributionIdentity:inv.Distribution,TargetAdmitted:cluster.ConnectionState!="REVOKED",CapabilityDiscoveryComplete:complete,ObservedCapabilities:inv.Capabilities,Disconnected:input.Disconnected,DuplicateStackResolved:complete})
	writeJSON(w,http.StatusOK,out)
}
