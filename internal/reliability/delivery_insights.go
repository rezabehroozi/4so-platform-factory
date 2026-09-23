package reliability

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const DeliveryInsightsAuthority = "DELIVERY_INSIGHTS_AUTHORITY_V1"

const (
	DeliveryEventDeploymentSucceeded = "DEPLOYMENT_SUCCEEDED"
	DeliveryEventDeploymentFailed    = "DEPLOYMENT_FAILED"
	DeliveryEventIncidentOpened      = "INCIDENT_OPENED"
	DeliveryEventIncidentResolved    = "INCIDENT_RESOLVED"

	DeliveryMetricObserved = "OBSERVED"
	DeliveryMetricUnknown  = "UNKNOWN"
)

type DeliveryEvidence struct {
	EvidenceID        string     `json:"evidenceId"`
	ProjectID         string     `json:"projectId"`
	EventType         string     `json:"eventType"`
	OccurredAt        time.Time  `json:"occurredAt"`
	OperationID       string     `json:"operationId,omitempty"`
	ReleaseDigest     string     `json:"releaseDigest,omitempty"`
	SourceCommittedAt *time.Time `json:"sourceCommittedAt,omitempty"`
	IncidentID        string     `json:"incidentId,omitempty"`
}

type DeliveryMetric struct {
	Status     string `json:"status"`
	Value      int64  `json:"value,omitempty"`
	Unit       string `json:"unit"`
	SampleSize int    `json:"sampleSize"`
}

type DeliveryInsights struct {
	Authority               string         `json:"authority"`
	ProjectID               string         `json:"projectId"`
	WindowStart             time.Time      `json:"windowStart"`
	WindowEnd               time.Time      `json:"windowEnd"`
	EvidenceCount           int            `json:"evidenceCount"`
	DeploymentFrequency     DeliveryMetric `json:"deploymentFrequency"`
	LeadTimeForChanges      DeliveryMetric `json:"leadTimeForChanges"`
	ChangeFailureRate       DeliveryMetric `json:"changeFailureRate"`
	FailedDeploymentRecovery DeliveryMetric `json:"failedDeploymentRecovery"`
	MissingEvidence         []string       `json:"missingEvidence,omitempty"`
	PhysicalCertificationInferred bool      `json:"physicalCertificationInferred"`
}

func observedMetric(value int64,unit string,n int)DeliveryMetric{return DeliveryMetric{Status:DeliveryMetricObserved,Value:value,Unit:unit,SampleSize:n}}
func unknownMetric(unit string)DeliveryMetric{return DeliveryMetric{Status:DeliveryMetricUnknown,Unit:unit}}

func BuildDeliveryInsights(projectID string,start,end time.Time,evidence []DeliveryEvidence)(DeliveryInsights,error){
	projectID=strings.TrimSpace(projectID);start=start.UTC();end=end.UTC()
	if projectID==""||start.IsZero()||end.IsZero()||!end.After(start){return DeliveryInsights{},fmt.Errorf("project and a positive delivery insight window are required")}
	out:=DeliveryInsights{Authority:DeliveryInsightsAuthority,ProjectID:projectID,WindowStart:start,WindowEnd:end,DeploymentFrequency:unknownMetric("deployments-per-day-micros"),LeadTimeForChanges:unknownMetric("seconds"),ChangeFailureRate:unknownMetric("basis-points"),FailedDeploymentRecovery:unknownMetric("seconds")}
	seen:=map[string]bool{};events:=make([]DeliveryEvidence,0,len(evidence))
	for _,event:=range evidence{
		event.EvidenceID=strings.TrimSpace(event.EvidenceID);event.ProjectID=strings.TrimSpace(event.ProjectID);event.EventType=strings.ToUpper(strings.TrimSpace(event.EventType));event.OccurredAt=event.OccurredAt.UTC()
		if event.ProjectID!=projectID||event.OccurredAt.Before(start)||!event.OccurredAt.Before(end){continue}
		if event.EvidenceID==""||seen[event.EvidenceID]{return DeliveryInsights{},fmt.Errorf("delivery evidence identity is empty or duplicated")}
		switch event.EventType{case DeliveryEventDeploymentSucceeded,DeliveryEventDeploymentFailed,DeliveryEventIncidentOpened,DeliveryEventIncidentResolved:default:return DeliveryInsights{},fmt.Errorf("unsupported delivery evidence event %q",event.EventType)}
		seen[event.EvidenceID]=true;events=append(events,event)
	}
	sort.Slice(events,func(i,j int)bool{if !events[i].OccurredAt.Equal(events[j].OccurredAt){return events[i].OccurredAt.Before(events[j].OccurredAt)};return events[i].EvidenceID<events[j].EvidenceID})
	out.EvidenceCount=len(events)
	deployments:=0;failed:=0;leadSeconds:=int64(0);leadSamples:=0
	opened:=map[string]time.Time{};recoverySeconds:=int64(0);recoverySamples:=0
	for _,event:=range events{
		switch event.EventType{
		case DeliveryEventDeploymentSucceeded,DeliveryEventDeploymentFailed:
			deployments++;if event.EventType==DeliveryEventDeploymentFailed{failed++}
			if event.SourceCommittedAt!=nil {committed:=event.SourceCommittedAt.UTC();if !committed.IsZero()&&!event.OccurredAt.Before(committed){leadSeconds+=int64(event.OccurredAt.Sub(committed).Seconds());leadSamples++}}
		case DeliveryEventIncidentOpened:
			id:=strings.TrimSpace(event.IncidentID);if id==""{return DeliveryInsights{},fmt.Errorf("incident-opened evidence requires incidentId")};if _,exists:=opened[id];exists{return DeliveryInsights{},fmt.Errorf("incident %s has duplicate open evidence",id)};opened[id]=event.OccurredAt
		case DeliveryEventIncidentResolved:
			id:=strings.TrimSpace(event.IncidentID);started,ok:=opened[id];if !ok{continue};if event.OccurredAt.Before(started){return DeliveryInsights{},fmt.Errorf("incident %s resolved before it opened",id)};recoverySeconds+=int64(event.OccurredAt.Sub(started).Seconds());recoverySamples++;delete(opened,id)
		}
	}
	windowSeconds:=int64(end.Sub(start).Seconds())
	if deployments>0&&windowSeconds>0{
		out.DeploymentFrequency=observedMetric(int64(deployments)*86400*1_000_000/windowSeconds,"deployments-per-day-micros",deployments)
		out.ChangeFailureRate=observedMetric(int64(failed)*10000/int64(deployments),"basis-points",deployments)
	}else{out.MissingEvidence=append(out.MissingEvidence,"deployment-events")}
	if leadSamples>0{out.LeadTimeForChanges=observedMetric(leadSeconds/int64(leadSamples),"seconds",leadSamples)}else{out.MissingEvidence=append(out.MissingEvidence,"source-commit-timestamps")}
	if recoverySamples>0{out.FailedDeploymentRecovery=observedMetric(recoverySeconds/int64(recoverySamples),"seconds",recoverySamples)}else{out.MissingEvidence=append(out.MissingEvidence,"matched-incident-open-resolve-pairs")}
	sort.Strings(out.MissingEvidence)
	return out,nil
}
