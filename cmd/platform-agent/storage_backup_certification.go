package main

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

type storageBackupAdapter struct {
	StorageClass           string
	StorageWaitForConsumer bool
	SnapshotClass          string
	VeleroNamespace        string
}

type storageClassList struct {
	Items []struct {
		Metadata struct {
			Name        string            `json:"name"`
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
		Provisioner       string `json:"provisioner"`
		VolumeBindingMode string `json:"volumeBindingMode"`
	} `json:"items"`
}

type volumeSnapshotClassList struct {
	Items []struct {
		Metadata struct {
			Name        string            `json:"name"`
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
		Driver string `json:"driver"`
	} `json:"items"`
}

type backupStorageLocationList struct {
	Items []struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Status struct {
			Phase string `json:"phase"`
		} `json:"status"`
	} `json:"items"`
}

func chooseDefaultClass(items []struct {
	Metadata struct {
		Name        string            `json:"name"`
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
}) string {
	names := []string{}
	for _, item := range items {
		name := strings.TrimSpace(item.Metadata.Name)
		if name == "" {
			continue
		}
		if strings.EqualFold(item.Metadata.Annotations["storageclass.kubernetes.io/is-default-class"], "true") || strings.EqualFold(item.Metadata.Annotations["storageclass.beta.kubernetes.io/is-default-class"], "true") || strings.EqualFold(item.Metadata.Annotations["snapshot.storage.kubernetes.io/is-default-class"], "true") {
			return name
		}
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

func (a *agent) discoverStorageBackupAdapter(ctx context.Context) (storageBackupAdapter, error) {
	var sc storageClassList
	if err := a.kubeJSON(ctx, http.MethodGet, "/apis/storage.k8s.io/v1/storageclasses", nil, &sc); err != nil {
		return storageBackupAdapter{}, fmt.Errorf("storage class discovery: %w", err)
	}
	storageClass := ""
	storageWait := false
	storageNames := []string{}
	storageModes := map[string]string{}
	storageProvisioners := map[string]string{}
	for _, item := range sc.Items {
		name := strings.TrimSpace(item.Metadata.Name)
		if name == "" {
			continue
		}
		storageNames = append(storageNames, name)
		storageModes[name] = strings.TrimSpace(item.VolumeBindingMode)
		storageProvisioners[name] = strings.TrimSpace(item.Provisioner)
		if strings.EqualFold(item.Metadata.Annotations["storageclass.kubernetes.io/is-default-class"], "true") || strings.EqualFold(item.Metadata.Annotations["storageclass.beta.kubernetes.io/is-default-class"], "true") {
			storageClass = name
		}
	}
	if storageClass == "" && len(storageNames) > 0 {
		sort.Strings(storageNames)
		storageClass = storageNames[0]
	}
	if storageClass == "" {
		return storageBackupAdapter{}, fmt.Errorf("no usable StorageClass is available")
	}
	storageWait = strings.EqualFold(storageModes[storageClass], "WaitForFirstConsumer")
	var snapshots volumeSnapshotClassList
	if err := a.kubeJSON(ctx, http.MethodGet, "/apis/snapshot.storage.k8s.io/v1/volumesnapshotclasses", nil, &snapshots); err != nil {
		return storageBackupAdapter{}, fmt.Errorf("VolumeSnapshotClass discovery: %w", err)
	}
	provisioner := storageProvisioners[storageClass]
	snapshotClass := ""
	snapshotNames := []string{}
	for _, item := range snapshots.Items {
		name := strings.TrimSpace(item.Metadata.Name)
		if name == "" || strings.TrimSpace(item.Driver) != provisioner {
			continue
		}
		snapshotNames = append(snapshotNames, name)
		if strings.EqualFold(item.Metadata.Annotations["snapshot.storage.kubernetes.io/is-default-class"], "true") {
			snapshotClass = name
		}
	}
	if snapshotClass == "" && len(snapshotNames) > 0 {
		sort.Strings(snapshotNames)
		snapshotClass = snapshotNames[0]
	}
	if snapshotClass == "" {
		return storageBackupAdapter{}, fmt.Errorf("no VolumeSnapshotClass matches StorageClass provisioner %s", provisioner)
	}
	if !a.kubeDiscoveryAvailable(ctx, "/apis/velero.io/v1") {
		return storageBackupAdapter{}, fmt.Errorf("velero.io/v1 API is not served")
	}
	var locations backupStorageLocationList
	if err := a.kubeJSON(ctx, http.MethodGet, "/apis/velero.io/v1/backupstoragelocations", nil, &locations); err != nil {
		return storageBackupAdapter{}, fmt.Errorf("Velero BackupStorageLocation discovery: %w", err)
	}
	wantedNamespace := strings.TrimSpace(a.cfg.BackupNamespace)
	namespaces := []string{}
	for _, item := range locations.Items {
		if !strings.EqualFold(strings.TrimSpace(item.Status.Phase), "Available") {
			continue
		}
		ns := strings.TrimSpace(item.Metadata.Namespace)
		if ns == "" || (wantedNamespace != "" && ns != wantedNamespace) {
			continue
		}
		namespaces = append(namespaces, ns)
	}
	if len(namespaces) == 0 {
		if wantedNamespace != "" {
			return storageBackupAdapter{}, fmt.Errorf("Velero namespace %s has no Available BackupStorageLocation", wantedNamespace)
		}
		return storageBackupAdapter{}, fmt.Errorf("Velero has no Available BackupStorageLocation")
	}
	sort.Strings(namespaces)
	namespace := namespaces[0]
	return storageBackupAdapter{StorageClass: storageClass, StorageWaitForConsumer: storageWait, SnapshotClass: snapshotClass, VeleroNamespace: namespace}, nil
}

func objectString(obj map[string]any, path ...string) string {
	var current any = obj
	for _, key := range path {
		m, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = m[key]
	}
	s, _ := current.(string)
	return s
}

func objectBool(obj map[string]any, path ...string) bool {
	var current any = obj
	for _, key := range path {
		m, ok := current.(map[string]any)
		if !ok {
			return false
		}
		current = m[key]
	}
	b, _ := current.(bool)
	return b
}

func (a *agent) waitKubeObject(ctx context.Context, path string, timeout time.Duration, ready func(map[string]any) bool) (map[string]any, error) {
	deadline := time.Now().Add(timeout)
	for {
		obj, found, err := a.getKubeObject(ctx, path)
		if err != nil {
			return nil, err
		}
		if found && ready(obj) {
			return obj, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for %s", path)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func runtimeCertificationExecutionIDForAttempt(runID string, attempt int) string {
	if attempt <= 1 {
		return runID
	}
	return fmt.Sprintf("a%d-%s", attempt, runID)
}

func runtimeCertificationExecutionID(task controlplane.RuntimeCertificationTask) string {
	return runtimeCertificationExecutionIDForAttempt(task.RunID, task.TaskAttempt)
}

func priorRuntimeCertificationCleanupRefs(task controlplane.RuntimeCertificationTask, generation controlplane.RuntimeCertificationCleanupGeneration, adapter storageBackupAdapter) []runtimeCertificationCleanupRef {
	executionID := runtimeCertificationExecutionIDForAttempt(task.RunID, generation.TaskAttempt)
	token := generation.Token
	refs := []runtimeCertificationCleanupRef{
		{Path: "/api/v1/namespaces/" + certificationNamespace("4so-cert-net-a", executionID), Owner: task.RunID, CleanupToken: token},
		{Path: "/api/v1/namespaces/" + certificationNamespace("4so-cert-net-b", executionID), Owner: task.RunID, CleanupToken: token},
	}
	if strings.TrimSpace(adapter.VeleroNamespace) == "" {
		return refs
	}
	pvcName := certName("4so-cert-pvc", executionID)
	snapName := certName("4so-cert-snap", executionID)
	restorePVC := certName("4so-cert-restore-pvc", executionID)
	probeCM := certName("4so-cert-backup-probe", executionID)
	backupName := certName("4so-cert-backup", executionID)
	restoreName := certName("4so-cert-restore", executionID)
	sourceProbe := certName("4so-cert-storage-probe", executionID+"-"+pvcName+"-write-read")
	restoreOwner := executionID + "-restore"
	restoredProbe := certName("4so-cert-storage-probe", restoreOwner+"-"+restorePVC+"-verify")
	refs = append(refs,
		runtimeCertificationCleanupRef{Path: "/apis/velero.io/v1/namespaces/" + adapter.VeleroNamespace + "/restores/" + restoreName, Owner: task.RunID, CleanupToken: token},
		runtimeCertificationCleanupRef{Path: "/apis/velero.io/v1/namespaces/" + adapter.VeleroNamespace + "/backups/" + backupName, Owner: task.RunID, CleanupToken: token},
		runtimeCertificationCleanupRef{Path: "/api/v1/namespaces/" + task.Namespace + "/configmaps/" + probeCM, Owner: task.RunID, CleanupToken: token},
		runtimeCertificationCleanupRef{Path: "/api/v1/namespaces/" + task.Namespace + "/pods/" + restoredProbe, Owner: restoreOwner, CleanupToken: token},
		runtimeCertificationCleanupRef{Path: "/api/v1/namespaces/" + task.Namespace + "/persistentvolumeclaims/" + restorePVC, Owner: task.RunID, CleanupToken: token},
		runtimeCertificationCleanupRef{Path: "/apis/snapshot.storage.k8s.io/v1/namespaces/" + task.Namespace + "/volumesnapshots/" + snapName, Owner: task.RunID, CleanupToken: token},
		runtimeCertificationCleanupRef{Path: "/api/v1/namespaces/" + task.Namespace + "/pods/" + sourceProbe, Owner: executionID, CleanupToken: token},
		runtimeCertificationCleanupRef{Path: "/api/v1/namespaces/" + task.Namespace + "/persistentvolumeclaims/" + pvcName, Owner: task.RunID, CleanupToken: token},
	)
	return refs
}

func (a *agent) cleanupPriorRuntimeCertificationAttempts(ctx context.Context, task controlplane.RuntimeCertificationTask) error {
	verifyGenerations := make([]controlplane.RuntimeCertificationCleanupGeneration, 0, len(task.PriorCleanupGenerations))
	for _, generation := range task.PriorCleanupGenerations {
		if generation.Phase == controlplane.RuntimeCertificationPhaseVerify && generation.TaskAttempt > 0 && strings.TrimSpace(generation.Token) != "" {
			verifyGenerations = append(verifyGenerations, generation)
		}
	}
	if len(verifyGenerations) == 0 {
		return nil
	}
	adapter, err := a.discoverStorageBackupAdapter(ctx)
	if err != nil {
		return fmt.Errorf("discover storage/backup adapter for prior-attempt cleanup: %w", err)
	}
	for _, generation := range verifyGenerations {
		for _, ref := range priorRuntimeCertificationCleanupRefs(task, generation, adapter) {
			if err := a.cleanupRuntimeCertificationEphemeralObject(ctx, ref, 30*time.Second); err != nil {
				return fmt.Errorf("cleanup prior runtime certification attempt %d resource %s: %w", generation.TaskAttempt, ref.Path, err)
			}
		}
	}
	return nil
}

func certName(prefix, runID string) string {
	suffix := strings.ToLower(strings.TrimPrefix(runID, "rtc_"))
	suffix = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		return '-'
	}, suffix)
	if len(suffix) > 24 {
		suffix = suffix[:24]
	}
	name := prefix + "-" + strings.Trim(suffix, "-")
	if len(name) > 63 {
		name = name[:63]
	}
	return strings.Trim(name, "-")
}

func (a *agent) runStorageProbePod(ctx context.Context, namespace, pvcName, runID, marker string, verifyOnly bool, cleanupToken string) (string, error) {
	if !strings.Contains(a.cfg.RuntimeProbeImage, "@sha256:") {
		return "", fmt.Errorf("digest-pinned runtime probe image is required for PVC I/O certification")
	}
	mode := "write-read"
	if verifyOnly {
		mode = "verify"
	}
	name := certName("4so-cert-storage-probe", runID+"-"+pvcName+"-"+mode)
	path := "/api/v1/namespaces/" + namespace + "/pods/" + name
	pod := map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": name, "namespace": namespace, "labels": map[string]any{"platform.4so.io/runtime-certification": runID, "platform.4so.io/storage-probe": mode}},
		"spec": map[string]any{
			"restartPolicy": "Never", "automountServiceAccountToken": false,
			"containers": []any{map[string]any{
				"name": "probe", "image": a.cfg.RuntimeProbeImage, "imagePullPolicy": "IfNotPresent",
				"env": []any{
					map[string]any{"name": "PLATFORM_PROBE_STORAGE_PATH", "value": "/cert-data/runtime-certification-marker"},
					map[string]any{"name": "PLATFORM_PROBE_STORAGE_MARKER", "value": marker},
					map[string]any{"name": "PLATFORM_PROBE_STORAGE_VERIFY_ONLY", "value": strconv.FormatBool(verifyOnly)},
				},
				"volumeMounts": []any{map[string]any{"name": "data", "mountPath": "/cert-data"}},
			}},
			"volumes": []any{map[string]any{"name": "data", "persistentVolumeClaim": map[string]any{"claimName": pvcName}}},
		},
	}
	if _, err := a.ensureRuntimeCertificationEphemeralObject(ctx, path, pod, runID, cleanupToken); err != nil {
		return "", err
	}
	deadline := time.Now().Add(120 * time.Second)
	for {
		obj, found, err := a.getKubeObject(ctx, path)
		if err != nil {
			return path, err
		}
		if found {
			switch objectString(obj, "status", "phase") {
			case "Succeeded":
				return path, nil
			case "Failed":
				return path, fmt.Errorf("storage probe pod %s failed", name)
			}
		}
		if time.Now().After(deadline) {
			return path, fmt.Errorf("timed out waiting for storage probe pod %s", name)
		}
		select {
		case <-ctx.Done():
			return path, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func blockedStorageChecks(detail string) []controlplane.RuntimeCheck {
	keys := []string{"pvc-bind", "pvc-io", "snapshot-create", "snapshot-restore-pvc", "snapshot-restore-io", "backup-create", "restore-validate"}
	out := make([]controlplane.RuntimeCheck, 0, len(keys))
	for _, key := range keys {
		out = append(out, controlplane.RuntimeCheck{Key: "target-runtime/" + key, Status: "BLOCKED", Detail: detail})
	}
	return out
}

func (a *agent) verifyStorageBackupRuntime(ctx context.Context, task controlplane.RuntimeCertificationTask) (checks []controlplane.RuntimeCheck, success bool, blocked bool, detail string) {
	if !strings.Contains(a.cfg.RuntimeProbeImage, "@sha256:") {
		detail := "digest-pinned runtime probe image is required for PVC I/O certification"
		return blockedStorageChecks(detail), false, true, detail
	}
	adapter, err := a.discoverStorageBackupAdapter(ctx)
	if err != nil {
		return blockedStorageChecks(err.Error()), false, true, "storage/backup runtime adapter is unavailable: " + err.Error()
	}

	executionID := runtimeCertificationExecutionID(task)
	pvcName := certName("4so-cert-pvc", executionID)
	snapName := certName("4so-cert-snap", executionID)
	restorePVC := certName("4so-cert-restore-pvc", executionID)
	probeCM := certName("4so-cert-backup-probe", executionID)
	backupName := certName("4so-cert-backup", executionID)
	restoreName := certName("4so-cert-restore", executionID)
	ns := task.Namespace
	checks = []controlplane.RuntimeCheck{}

	pvcPath := "/api/v1/namespaces/" + ns + "/persistentvolumeclaims/" + pvcName
	sourceProbePath := ""
	restoredProbePath := ""
	snapPath := "/apis/snapshot.storage.k8s.io/v1/namespaces/" + ns + "/volumesnapshots/" + snapName
	restoredPVCPath := "/api/v1/namespaces/" + ns + "/persistentvolumeclaims/" + restorePVC
	probePath := "/api/v1/namespaces/" + ns + "/configmaps/" + probeCM
	backupPath := "/apis/velero.io/v1/namespaces/" + adapter.VeleroNamespace + "/backups/" + backupName
	restorePath := "/apis/velero.io/v1/namespaces/" + adapter.VeleroNamespace + "/restores/" + restoreName
	cleanupRefs := []runtimeCertificationCleanupRef{}
	track := func(path, owner string) (runtimeCertificationCleanupRef, error) {
		ref, err := a.runtimeCertificationCleanupRef(ctx, path, owner, task.CleanupToken)
		if err != nil {
			return runtimeCertificationCleanupRef{}, err
		}
		cleanupRefs = append(cleanupRefs, ref)
		return ref, nil
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		var cleanupErrs []string
		for i := len(cleanupRefs) - 1; i >= 0; i-- {
			if cleanupRefs[i].Path == "" {
				continue
			}
			if err := a.cleanupRuntimeCertificationEphemeralObject(cleanup, cleanupRefs[i], 10*time.Second); err != nil {
				cleanupErrs = append(cleanupErrs, cleanupRefs[i].Path+": "+err.Error())
			}
		}
		if len(cleanupErrs) > 0 {
			cleanupDetail := "runtime certification storage cleanup failed: " + strings.Join(cleanupErrs, "; ")
			checks = append(checks, check("target-runtime/storage-cleanup", time.Now(), false, cleanupDetail))
			success = false
			if detail == "" {
				detail = cleanupDetail
			} else {
				detail += "; " + cleanupDetail
			}
		}
	}()

	started := time.Now()
	pvc := map[string]any{"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": map[string]any{"name": pvcName, "namespace": ns, "labels": map[string]any{"platform.4so.io/runtime-certification": task.RunID}}, "spec": map[string]any{"accessModes": []any{"ReadWriteOnce"}, "storageClassName": adapter.StorageClass, "resources": map[string]any{"requests": map[string]any{"storage": "64Mi"}}}}
	if _, err = a.ensureRuntimeCertificationEphemeralObject(ctx, pvcPath, pvc, task.RunID, task.CleanupToken); err != nil {
		checks = append(checks, check("target-runtime/pvc-bind", started, false, err.Error()))
		return checks, false, false, err.Error()
	}
	if _, err = track(pvcPath, task.RunID); err != nil {
		return checks, false, false, err.Error()
	}
	marker := "4so-pvc-io-" + task.RunID
	ioStarted := time.Now()
	if adapter.StorageWaitForConsumer {
		sourceProbePath, err = a.runStorageProbePod(ctx, ns, pvcName, executionID, marker, false, task.CleanupToken)
		if err != nil {
			checks = append(checks, check("target-runtime/pvc-bind", started, false, "WaitForFirstConsumer probe could not provision PVC: "+err.Error()))
			checks = append(checks, check("target-runtime/pvc-io", ioStarted, false, err.Error()))
			return checks, false, false, err.Error()
		}
	}
	_, err = a.waitKubeObject(ctx, pvcPath, 90*time.Second, func(v map[string]any) bool { return objectString(v, "status", "phase") == "Bound" })
	checks = append(checks, check("target-runtime/pvc-bind", started, err == nil, "PVC bound using StorageClass="+adapter.StorageClass))
	if err != nil {
		return checks, false, false, err.Error()
	}
	if !adapter.StorageWaitForConsumer {
		sourceProbePath, err = a.runStorageProbePod(ctx, ns, pvcName, executionID, marker, false, task.CleanupToken)
	}
	if err == nil && sourceProbePath != "" {
		if _, trackErr := track(sourceProbePath, executionID); trackErr != nil {
			return checks, false, false, trackErr.Error()
		}
	}
	checks = append(checks, check("target-runtime/pvc-io", ioStarted, err == nil, "digest-pinned platform-probe wrote and read the PVC marker"))
	if err != nil {
		return checks, false, false, err.Error()
	}

	started = time.Now()
	snapshot := map[string]any{"apiVersion": "snapshot.storage.k8s.io/v1", "kind": "VolumeSnapshot", "metadata": map[string]any{"name": snapName, "namespace": ns, "labels": map[string]any{"platform.4so.io/runtime-certification": task.RunID}}, "spec": map[string]any{"volumeSnapshotClassName": adapter.SnapshotClass, "source": map[string]any{"persistentVolumeClaimName": pvcName}}}
	if _, err = a.ensureRuntimeCertificationEphemeralObject(ctx, snapPath, snapshot, task.RunID, task.CleanupToken); err != nil {
		checks = append(checks, check("target-runtime/snapshot-create", started, false, err.Error()))
		return checks, false, false, err.Error()
	}
	if _, err = track(snapPath, task.RunID); err != nil {
		return checks, false, false, err.Error()
	}
	_, err = a.waitKubeObject(ctx, snapPath, 90*time.Second, func(v map[string]any) bool { return objectBool(v, "status", "readyToUse") })
	checks = append(checks, check("target-runtime/snapshot-create", started, err == nil, "VolumeSnapshot readyToUse via class="+adapter.SnapshotClass))
	if err != nil {
		return checks, false, false, err.Error()
	}

	started = time.Now()
	restored := map[string]any{"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": map[string]any{"name": restorePVC, "namespace": ns, "labels": map[string]any{"platform.4so.io/runtime-certification": task.RunID}}, "spec": map[string]any{"accessModes": []any{"ReadWriteOnce"}, "storageClassName": adapter.StorageClass, "dataSource": map[string]any{"apiGroup": "snapshot.storage.k8s.io", "kind": "VolumeSnapshot", "name": snapName}, "resources": map[string]any{"requests": map[string]any{"storage": "64Mi"}}}}
	if _, err = a.ensureRuntimeCertificationEphemeralObject(ctx, restoredPVCPath, restored, task.RunID, task.CleanupToken); err != nil {
		checks = append(checks, check("target-runtime/snapshot-restore-pvc", started, false, err.Error()))
		return checks, false, false, err.Error()
	}
	if _, err = track(restoredPVCPath, task.RunID); err != nil {
		return checks, false, false, err.Error()
	}
	restoreIOStarted := time.Now()
	if adapter.StorageWaitForConsumer {
		restoredProbePath, err = a.runStorageProbePod(ctx, ns, restorePVC, executionID+"-restore", marker, true, task.CleanupToken)
		if err != nil {
			checks = append(checks, check("target-runtime/snapshot-restore-pvc", started, false, "restored WaitForFirstConsumer PVC could not be mounted: "+err.Error()))
			checks = append(checks, check("target-runtime/snapshot-restore-io", restoreIOStarted, false, err.Error()))
			return checks, false, false, err.Error()
		}
	}
	_, err = a.waitKubeObject(ctx, restoredPVCPath, 90*time.Second, func(v map[string]any) bool { return objectString(v, "status", "phase") == "Bound" })
	checks = append(checks, check("target-runtime/snapshot-restore-pvc", started, err == nil, "PVC restored from VolumeSnapshot and bound"))
	if err != nil {
		return checks, false, false, err.Error()
	}
	if !adapter.StorageWaitForConsumer {
		restoredProbePath, err = a.runStorageProbePod(ctx, ns, restorePVC, executionID+"-restore", marker, true, task.CleanupToken)
	}
	if err == nil && restoredProbePath != "" {
		if _, trackErr := track(restoredProbePath, executionID+"-restore"); trackErr != nil {
			return checks, false, false, trackErr.Error()
		}
	}
	checks = append(checks, check("target-runtime/snapshot-restore-io", restoreIOStarted, err == nil, "digest-pinned platform-probe read the original marker from the snapshot-restored PVC"))
	if err != nil {
		return checks, false, false, err.Error()
	}

	backupMarker := "4so-runtime-certification-" + task.RunID
	cm := map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": probeCM, "namespace": ns, "labels": map[string]any{"platform.4so.io/runtime-certification": task.RunID, "platform.4so.io/backup-probe": "true"}}, "data": map[string]any{"marker": backupMarker}}
	if _, err = a.ensureRuntimeCertificationEphemeralObject(ctx, probePath, cm, task.RunID, task.CleanupToken); err != nil {
		return append(checks, check("target-runtime/backup-create", time.Now(), false, err.Error())), false, false, err.Error()
	}
	probeRef, trackErr := track(probePath, task.RunID)
	if trackErr != nil {
		return checks, false, false, trackErr.Error()
	}

	started = time.Now()
	backup := map[string]any{"apiVersion": "velero.io/v1", "kind": "Backup", "metadata": map[string]any{"name": backupName, "namespace": adapter.VeleroNamespace, "labels": map[string]any{"platform.4so.io/runtime-certification": task.RunID}}, "spec": map[string]any{"includedNamespaces": []any{ns}, "includedResources": []any{"configmaps"}, "labelSelector": map[string]any{"matchLabels": map[string]any{"platform.4so.io/backup-probe": "true"}}, "snapshotVolumes": false}}
	if _, err = a.ensureRuntimeCertificationEphemeralObject(ctx, backupPath, backup, task.RunID, task.CleanupToken); err != nil {
		checks = append(checks, check("target-runtime/backup-create", started, false, err.Error()))
		return checks, false, false, err.Error()
	}
	if _, err = track(backupPath, task.RunID); err != nil {
		return checks, false, false, err.Error()
	}
	_, err = a.waitKubeObject(ctx, backupPath, 120*time.Second, func(v map[string]any) bool { return objectString(v, "status", "phase") == "Completed" })
	checks = append(checks, check("target-runtime/backup-create", started, err == nil, "Velero Backup completed in namespace="+adapter.VeleroNamespace))
	if err != nil {
		return checks, false, false, err.Error()
	}

	if err = a.cleanupRuntimeCertificationEphemeralObject(ctx, probeRef, 30*time.Second); err != nil {
		return checks, false, false, err.Error()
	}
	for i := range cleanupRefs {
		if cleanupRefs[i].Path == probePath && cleanupRefs[i].UID == probeRef.UID {
			cleanupRefs[i].Path = ""
		}
	}
	started = time.Now()
	restore := map[string]any{"apiVersion": "velero.io/v1", "kind": "Restore", "metadata": map[string]any{"name": restoreName, "namespace": adapter.VeleroNamespace, "labels": map[string]any{"platform.4so.io/runtime-certification": task.RunID}}, "spec": map[string]any{"backupName": backupName, "includedNamespaces": []any{ns}, "includedResources": []any{"configmaps"}}}
	if _, err = a.ensureRuntimeCertificationEphemeralObject(ctx, restorePath, restore, task.RunID, task.CleanupToken); err != nil {
		checks = append(checks, check("target-runtime/restore-validate", started, false, err.Error()))
		return checks, false, false, err.Error()
	}
	if _, err = track(restorePath, task.RunID); err != nil {
		return checks, false, false, err.Error()
	}
	_, err = a.waitKubeObject(ctx, restorePath, 120*time.Second, func(v map[string]any) bool { return objectString(v, "status", "phase") == "Completed" })
	if err == nil {
		var probe map[string]any
		var found bool
		probe, found, err = a.getKubeObject(ctx, probePath)
		if err == nil && (!found || !runtimeCertificationEphemeralOwnedBy(probe, task.RunID, task.CleanupToken) || objectString(probe, "data", "marker") != backupMarker) {
			err = fmt.Errorf("restored ConfigMap identity or marker mismatch")
		}
		if err == nil {
			if _, trackErr := track(probePath, task.RunID); trackErr != nil {
				err = trackErr
			}
		}
	}
	checks = append(checks, check("target-runtime/restore-validate", started, err == nil, "Velero Restore completed and deleted probe ConfigMap was recovered with matching marker"))
	if err != nil {
		return checks, false, false, err.Error()
	}
	return checks, true, false, ""
}

func (a *agent) storageBackupCapabilities(ctx context.Context) ([]string, bool) {
	if !strings.Contains(a.cfg.RuntimeProbeImage, "@sha256:") {
		return nil, false
	}
	adapter, err := a.discoverStorageBackupAdapter(ctx)
	if err != nil {
		return nil, false
	}
	caps := []string{"cert.pvc", "cert.snapshot", "cert.backup", "cert.restore"}
	if adapter.StorageClass != "" && adapter.SnapshotClass != "" && adapter.VeleroNamespace != "" {
		return caps, true
	}
	return nil, false
}

func storageBackupEvidenceSummary(checks []controlplane.RuntimeCheck) string {
	pass := 0
	for _, item := range checks {
		if item.Status == "PASS" {
			pass++
		}
	}
	return "storage-backup executable checks=" + strconv.Itoa(pass) + "/" + strconv.Itoa(len(checks))
}
