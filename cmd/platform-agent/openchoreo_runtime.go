package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"platform.4so.io/factory/internal/openchoreo"
)

const (
	openChoreoExecutorAuthority = "OPENCHOREO_TARGET_EXECUTOR_JOB_AUTHORITY_V1"
	openChoreoExecutorJobLabel = "platform.4so.io/openchoreo-runtime-executor"
	openChoreoReceiptName = "4so-openchoreo-runtime"
	openChoreoReceiptAuthority = "OPENCHOREO_TARGET_OBSERVED_RECEIPT_V1"
)

type openChoreoAgentTask struct {
	OperationID       string                      `json:"operationId"`
	OperationRevision int64                       `json:"operationRevision"`
	TaskFenceToken    int64                       `json:"taskFenceToken"`
	LeaseExpiresAt    time.Time                   `json:"leaseExpiresAt"`
	Request           openchoreo.LifecycleRequest `json:"request"`
	RuntimeSource     openchoreo.RuntimeSource    `json:"runtimeSource"`
}

type openChoreoAgentResult struct {
	TaskFenceToken       int64  `json:"taskFenceToken"`
	Success              bool   `json:"success"`
	RecoveryRequired     bool   `json:"recoveryRequired,omitempty"`
	Installed            bool   `json:"installed"`
	ObservedSourceDigest string `json:"observedSourceDigest,omitempty"`
	Version              string `json:"version,omitempty"`
	UpstreamCommit       string `json:"upstreamCommit,omitempty"`
	Phase                string `json:"phase,omitempty"`
	Error                string `json:"error,omitempty"`
}

func openChoreoObjectName(prefix, operationID string, fence int64) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(operationID)))
	return prefix + hex.EncodeToString(sum[:6]) + "-" + strconv.FormatInt(fence, 10)
}

func openChoreoExecutorJobName(task openChoreoAgentTask) string {
	return openChoreoObjectName("oc-exec-", task.OperationID, task.TaskFenceToken)
}

func openChoreoExecutorJobPath(namespace string, task openChoreoAgentTask) string {
	return "/apis/batch/v1/namespaces/" + url.PathEscape(namespace) + "/jobs/" + url.PathEscape(openChoreoExecutorJobName(task))
}

func validateOpenChoreoAgentTask(task openChoreoAgentTask, clusterID string) error {
	if strings.TrimSpace(task.OperationID) == "" || task.OperationRevision <= 0 || task.TaskFenceToken <= 0 || task.LeaseExpiresAt.IsZero() || !task.LeaseExpiresAt.After(time.Now().UTC()) {
		return fmt.Errorf("OpenChoreo lifecycle task identity/fence is invalid")
	}
	req, err := openchoreo.CanonicalLifecycleRequest(task.Request)
	if err != nil { return err }
	if req.ClusterID != strings.TrimSpace(clusterID) {
		return fmt.Errorf("OpenChoreo lifecycle task cluster does not match this agent")
	}
	if err = openchoreo.ValidateRuntimeExecutionSource(task.RuntimeSource); err != nil {
		return fmt.Errorf("OpenChoreo runtime source is not execution eligible: %w", err)
	}
	digest, err := openchoreo.RuntimeSourceDigest(task.RuntimeSource)
	if err != nil { return err }
	if digest != req.RuntimeSourceDigest {
		return fmt.Errorf("OpenChoreo task runtime source digest does not match sealed lifecycle request")
	}
	return nil
}

func openChoreoExecutorJob(task openChoreoAgentTask, namespace, serviceAccount string) (map[string]any, error) {
	sourceRaw, err := json.Marshal(task.RuntimeSource)
	if err != nil { return nil, err }
	suppressionsRaw, err := json.Marshal(task.Request.NativeCapabilitySuppressions)
	if err != nil { return nil, err }
	action := strings.ToLower(string(task.Request.Action))
	annotations := map[string]any{
		"platform.4so.io/authority": openChoreoExecutorAuthority,
		"platform.4so.io/operation-id": task.OperationID,
		"platform.4so.io/task-fence-token": strconv.FormatInt(task.TaskFenceToken, 10),
		"platform.4so.io/runtime-source-digest": task.Request.RuntimeSourceDigest,
		"platform.4so.io/lifecycle-action": string(task.Request.Action),
	}
	labels := map[string]any{openChoreoExecutorJobLabel:"true","platform.4so.io/managed":"true"}
	return map[string]any{
		"apiVersion":"batch/v1","kind":"Job",
		"metadata":map[string]any{"name":openChoreoExecutorJobName(task),"namespace":namespace,"labels":labels,"annotations":annotations},
		"spec":map[string]any{
			"backoffLimit":0,"ttlSecondsAfterFinished":86400,
			"template":map[string]any{
				"metadata":map[string]any{"labels":labels,"annotations":annotations},
				"spec":map[string]any{
					"serviceAccountName":serviceAccount,"restartPolicy":"Never",
					"securityContext":map[string]any{"runAsNonRoot":true,"seccompProfile":map[string]any{"type":"RuntimeDefault"}},
					"containers":[]any{map[string]any{
						"name":"executor","image":task.RuntimeSource.ExecutorImageReference,"imagePullPolicy":"IfNotPresent",
						"args":[]any{"lifecycle","--action",action,"--receipt-namespace",namespace,"--receipt-name",openChoreoReceiptName},
						"env":[]any{
							map[string]any{"name":"FOURSO_OPENCHOREO_RUNTIME_SOURCE_JSON","value":string(sourceRaw)},
							map[string]any{"name":"FOURSO_OPENCHOREO_RUNTIME_SOURCE_DIGEST","value":task.Request.RuntimeSourceDigest},
							map[string]any{"name":"FOURSO_OPENCHOREO_OPERATION_ID","value":task.OperationID},
							map[string]any{"name":"FOURSO_OPENCHOREO_TASK_FENCE_TOKEN","value":strconv.FormatInt(task.TaskFenceToken,10)},
							map[string]any{"name":"FOURSO_OPENCHOREO_EXPECTED_OBSERVED_SOURCE_DIGEST","value":task.Request.ExpectedObservedSourceDigest},
							map[string]any{"name":"FOURSO_OPENCHOREO_NATIVE_SUPPRESSIONS_JSON","value":string(suppressionsRaw)},
							map[string]any{"name":"FOURSO_OPENCHOREO_RECEIPT_AUTHORITY","value":openChoreoReceiptAuthority},
						},
						"securityContext":map[string]any{"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"capabilities":map[string]any{"drop":[]any{"ALL"}}},
						"volumeMounts":[]any{
							map[string]any{"name":"tmp","mountPath":"/tmp"},
							map[string]any{"name":"helm-cache","mountPath":"/home/nonroot/.cache/helm"},
							map[string]any{"name":"helm-config","mountPath":"/home/nonroot/.config/helm"},
						},
					}},
					"volumes":[]any{
						map[string]any{"name":"tmp","emptyDir":map[string]any{}},
						map[string]any{"name":"helm-cache","emptyDir":map[string]any{}},
						map[string]any{"name":"helm-config","emptyDir":map[string]any{}},
					},
				},
			},
		},
	},nil
}

func openChoreoExecutorJobOwnership(job map[string]any, task openChoreoAgentTask, namespace string) error {
	if job["apiVersion"] != "batch/v1" || job["kind"] != "Job" { return fmt.Errorf("OpenChoreo executor object identity is invalid") }
	meta,_:=job["metadata"].(map[string]any)
	if strings.TrimSpace(fmt.Sprint(meta["name"])) != openChoreoExecutorJobName(task) || strings.TrimSpace(fmt.Sprint(meta["namespace"])) != strings.TrimSpace(namespace) {
		return fmt.Errorf("OpenChoreo executor Job metadata does not match task fence")
	}
	annotations,_:=meta["annotations"].(map[string]any)
	want:=map[string]string{
		"platform.4so.io/authority":openChoreoExecutorAuthority,
		"platform.4so.io/operation-id":task.OperationID,
		"platform.4so.io/task-fence-token":strconv.FormatInt(task.TaskFenceToken,10),
		"platform.4so.io/runtime-source-digest":task.Request.RuntimeSourceDigest,
		"platform.4so.io/lifecycle-action":string(task.Request.Action),
	}
	for k,v:=range want { if strings.TrimSpace(fmt.Sprint(annotations[k]))!=v { return fmt.Errorf("OpenChoreo executor Job ownership mismatch for %s",k) } }
	spec,_:=job["spec"].(map[string]any);tmpl,_:=spec["template"].(map[string]any);pod,_:=tmpl["spec"].(map[string]any);containers,_:=pod["containers"].([]any)
	if len(containers)!=1 { return fmt.Errorf("OpenChoreo executor Job container identity is invalid") }
	container,_:=containers[0].(map[string]any)
	if strings.TrimSpace(fmt.Sprint(container["image"]))!=task.RuntimeSource.ExecutorImageReference { return fmt.Errorf("OpenChoreo executor image does not match exact runtime source") }
	return nil
}

func openChoreoJobTerminal(job map[string]any) (done, failed bool, phase string) {
	status,_:=job["status"].(map[string]any);conditions,_:=status["conditions"].([]any)
	for _,raw:=range conditions {
		condition,_:=raw.(map[string]any)
		if strings.TrimSpace(fmt.Sprint(condition["status"]))!="True" { continue }
		switch strings.TrimSpace(fmt.Sprint(condition["type"])) {
		case "Complete": return true,false,"ExecutorComplete"
		case "Failed": return true,true,"ExecutorFailed"
		}
	}
	return false,false,"ExecutorRunning"
}

func (a *agent) nextOpenChoreoLifecycleTask(ctx context.Context) (openChoreoAgentTask,bool,error) {
	var task openChoreoAgentTask
	endpoint:=a.cfg.Hub+"/agent/v1/clusters/"+a.clusterID+"/openchoreo-tasks/next"
	req,err:=http.NewRequestWithContext(ctx,http.MethodGet,endpoint,nil);if err!=nil{return task,false,err}
	res,err:=a.hub.Do(req);if err!=nil{return task,false,err};defer res.Body.Close()
	if res.StatusCode==http.StatusNoContent{return task,false,nil}
	if res.StatusCode/100!=2{raw,_:=io.ReadAll(io.LimitReader(res.Body,4096));return task,false,fmt.Errorf("OpenChoreo task API %s: %s",res.Status,string(raw))}
	if err=json.NewDecoder(res.Body).Decode(&task);err!=nil{return task,false,err}
	return task,true,nil
}

func (a *agent) dispatchOpenChoreoExecutor(ctx context.Context, task openChoreoAgentTask) openChoreoAgentResult {
	result:=openChoreoAgentResult{TaskFenceToken:task.TaskFenceToken}
	if strings.TrimSpace(a.cfg.ServiceAccount)=="" { result.Error="OpenChoreo executor requires import-scoped agent service account";return result }
	path:=openChoreoExecutorJobPath(a.cfg.Namespace,task)
	current,found,err:=a.getKubeObject(ctx,path)
	if err!=nil { result.RecoveryRequired=true;result.Error="OpenChoreo executor pre-mutation readback failed: "+err.Error();return result }
	if found {
		if err=openChoreoExecutorJobOwnership(current,task,a.cfg.Namespace);err!=nil{result.RecoveryRequired=true;result.Error=err.Error();return result}
	} else {
		job,buildErr:=openChoreoExecutorJob(task,a.cfg.Namespace,a.cfg.ServiceAccount)
		if buildErr!=nil{result.Error=buildErr.Error();return result}
		collection:="/apis/batch/v1/namespaces/"+url.PathEscape(a.cfg.Namespace)+"/jobs"
		_,conflict,createErr:=a.createKubeObject(ctx,collection,job)
		if createErr!=nil {
			current,found,err=a.getKubeObject(ctx,path)
			if err!=nil||!found {result.RecoveryRequired=true;result.Error="OpenChoreo executor Job mutation outcome is unknown: "+createErr.Error();return result}
			if ownErr:=openChoreoExecutorJobOwnership(current,task,a.cfg.Namespace);ownErr!=nil{result.RecoveryRequired=true;result.Error=ownErr.Error();return result}
		}
		if conflict {
			current,found,err=a.getKubeObject(ctx,path)
			if err!=nil||!found {result.RecoveryRequired=true;result.Error="OpenChoreo executor Job conflict lacks authoritative readback";return result}
			if ownErr:=openChoreoExecutorJobOwnership(current,task,a.cfg.Namespace);ownErr!=nil{result.RecoveryRequired=true;result.Error=ownErr.Error();return result}
		}
	}
	deadline:=task.LeaseExpiresAt.Add(-10*time.Second)
	for time.Now().UTC().Before(deadline) {
		current,found,err=a.getKubeObject(ctx,path)
		if err!=nil {result.RecoveryRequired=true;result.Error="OpenChoreo executor Job readback failed: "+err.Error();return result}
		if !found {result.RecoveryRequired=true;result.Error="OpenChoreo executor Job disappeared after dispatch";return result}
		if err=openChoreoExecutorJobOwnership(current,task,a.cfg.Namespace);err!=nil{result.RecoveryRequired=true;result.Error=err.Error();return result}
		done,failed,phase:=openChoreoJobTerminal(current);result.Phase=phase
		if done {
			if failed {
				// The executor may have crossed the Helm mutation boundary before the Job failed.
				// Never classify that outcome as safely replayable without authoritative readback.
				result.RecoveryRequired=true
				result.Error="OpenChoreo executor Job failed after mutation dispatch; authoritative recovery readback is required"
				return result
			}
			return a.readOpenChoreoReceipt(ctx,task)
		}
		select {case <-ctx.Done():result.RecoveryRequired=true;result.Error="OpenChoreo executor interrupted after mutation dispatch";return result;case <-time.After(3*time.Second):}
	}
	result.RecoveryRequired=true
	result.Error="OpenChoreo executor lease deadline reached before authoritative terminal readback"
	return result
}

func (a *agent) readOpenChoreoReceipt(ctx context.Context,task openChoreoAgentTask) openChoreoAgentResult {
	result:=openChoreoAgentResult{TaskFenceToken:task.TaskFenceToken,Phase:"ReceiptReadback"}
	path:="/api/v1/namespaces/"+url.PathEscape(a.cfg.Namespace)+"/configmaps/"+url.PathEscape(openChoreoReceiptName)
	obj,found,err:=a.getKubeObject(ctx,path)
	if err!=nil||!found {result.RecoveryRequired=true;result.Error="OpenChoreo observed receipt is unavailable after executor completion";if err!=nil{result.Error+=": "+err.Error()};return result}
	meta,_:=obj["metadata"].(map[string]any);annotations,_:=meta["annotations"].(map[string]any);data,_:=obj["data"].(map[string]any)
	if strings.TrimSpace(fmt.Sprint(annotations["platform.4so.io/authority"]))!=openChoreoReceiptAuthority {
		result.RecoveryRequired=true;result.Error="OpenChoreo observed receipt authority mismatch";return result
	}
	if strings.TrimSpace(fmt.Sprint(data["operationId"]))!=task.OperationID || strings.TrimSpace(fmt.Sprint(data["taskFenceToken"]))!=strconv.FormatInt(task.TaskFenceToken,10) {
		result.RecoveryRequired=true;result.Error="OpenChoreo observed receipt operation/fence mismatch";return result
	}
	installed:=strings.EqualFold(strings.TrimSpace(fmt.Sprint(data["installed"])),"true")
	wantInstalled:=task.Request.Action!=openchoreo.ActionRemove
	if installed!=wantInstalled {result.RecoveryRequired=true;result.Error="OpenChoreo observed receipt installed state does not match lifecycle action";return result}
	result.Installed=installed
	result.ObservedSourceDigest=strings.TrimSpace(fmt.Sprint(data["runtimeSourceDigest"]))
	result.Version=strings.TrimSpace(fmt.Sprint(data["version"]))
	result.UpstreamCommit=strings.TrimSpace(fmt.Sprint(data["upstreamCommit"]))
	result.Phase=strings.TrimSpace(fmt.Sprint(data["phase"]));if result.Phase==""{result.Phase="Observed"}
	if installed && (result.ObservedSourceDigest!=task.Request.RuntimeSourceDigest || result.Version!=task.RuntimeSource.Version || result.UpstreamCommit!=task.RuntimeSource.UpstreamCommit) {
		result.RecoveryRequired=true;result.Error="OpenChoreo observed receipt does not match exact admitted runtime source";return result
	}
	result.Success=true
	return result
}

func (a *agent) reportOpenChoreoLifecycleTask(ctx context.Context,task openChoreoAgentTask,result openChoreoAgentResult) error {
	raw,err:=json.Marshal(result);if err!=nil{return err}
	endpoint:=a.cfg.Hub+"/agent/v1/clusters/"+a.clusterID+"/openchoreo-tasks/"+url.PathEscape(task.OperationID)+"/result"
	req,err:=http.NewRequestWithContext(ctx,http.MethodPost,endpoint,bytes.NewReader(raw));if err!=nil{return err}
	req.Header.Set("Content-Type","application/json");req.Header.Set("If-Match",fmt.Sprintf("%q",strconv.FormatInt(task.OperationRevision,10)))
	res,err:=a.hub.Do(req);if err!=nil{return err};defer res.Body.Close()
	if res.StatusCode/100!=2{body,_:=io.ReadAll(io.LimitReader(res.Body,4096));return fmt.Errorf("OpenChoreo task result API %s: %s",res.Status,string(body))}
	return nil
}

func (a *agent) processOpenChoreoLifecycleTask(ctx context.Context) error {
	task,ok,err:=a.nextOpenChoreoLifecycleTask(ctx);if err!=nil||!ok{return err}
	if err=validateOpenChoreoAgentTask(task,a.clusterID);err!=nil {
		return a.reportOpenChoreoLifecycleTask(ctx,task,openChoreoAgentResult{TaskFenceToken:task.TaskFenceToken,RecoveryRequired:true,Error:err.Error()})
	}
	result:=a.dispatchOpenChoreoExecutor(ctx,task)
	return a.reportOpenChoreoLifecycleTask(ctx,task,result)
}
