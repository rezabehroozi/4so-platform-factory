package api

import (
	"net/http"
	"strings"
	"time"
	"platform.4so.io/factory/internal/reliability"
)

func parseDeliveryInsightsWindow(r *http.Request) (time.Time,time.Time,error) {
	from,err:=time.Parse(time.RFC3339,strings.TrimSpace(r.URL.Query().Get("from")));if err!=nil{return time.Time{},time.Time{},err}
	to,err:=time.Parse(time.RFC3339,strings.TrimSpace(r.URL.Query().Get("to")));if err!=nil{return time.Time{},time.Time{},err}
	if !to.After(from){return time.Time{},time.Time{},reliability.ErrInvalidDeliveryWindow};return from.UTC(),to.UTC(),nil
}
func (s *Server) reliabilityDeliveryInsights(w http.ResponseWriter,r *http.Request){
	projectID:=strings.TrimSpace(r.URL.Query().Get("projectId"));if projectID==""{writeError(w,http.StatusUnprocessableEntity,"PROJECT_REQUIRED","projectId is required");return}
	if _,err:=s.requireProjectAccess(r,projectID,organizationRead);err!=nil{writeScopeError(w,err);return}
	from,to,err:=parseDeliveryInsightsWindow(r);if err!=nil{writeError(w,http.StatusUnprocessableEntity,"DELIVERY_WINDOW_INVALID","from/to must be RFC3339 and to must be after from");return}
	store,ok:=s.reliabilityStore();if !ok{writeReliabilityStoreUnavailable(w);return}
	incidents,err:=store.ListIncidents(r.Context(),projectID,"",1000);if err!=nil{writeStoreError(w,err);return}
	evidence:=make([]reliability.DeliveryEvidence,0,len(incidents)*2)
	for _,incident:=range incidents{
		evidence=append(evidence,reliability.DeliveryEvidence{EvidenceID:"incident-opened:"+incident.ID,ProjectID:projectID,EventType:reliability.DeliveryIncidentOpened,OccurredAt:incident.CreatedAt,IncidentID:incident.ID})
		if incident.State==reliability.IncidentResolved{evidence=append(evidence,reliability.DeliveryEvidence{EvidenceID:"incident-resolved:"+incident.ID,ProjectID:projectID,EventType:reliability.DeliveryIncidentResolved,OccurredAt:incident.UpdatedAt,IncidentID:incident.ID})}
	}
	insights,err:=reliability.BuildDeliveryInsights(projectID,from,to,evidence);if err!=nil{writeError(w,http.StatusUnprocessableEntity,"DELIVERY_INSIGHTS_INVALID",err.Error());return};writeJSON(w,http.StatusOK,insights)
}
