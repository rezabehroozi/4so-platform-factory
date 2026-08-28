package lifecycle

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"platform.4so.io/factory/internal/bootstrap"
)

func backupJobManifest(service, id, jobName, operationID, backupRoot string, bundle bootstrap.BundleManifest, profileID, executionNode string) string {
	pvc := ""
	database := ""
	switch service {
	case "forgejo":
		pvc = "data-platform-forgejo-0"
		database = "forgejo"
	case "zot":
		pvc = "platform-zot-data"
	case "keycloak":
		database = "keycloak"
	}
	init := ""
	if database != "" {
		dbUser, dbSecret := databaseCredentials(service, profileID)
		init = fmt.Sprintf(`
      initContainers:
        - name: database-backup
          image: %s
          env:
            - name: PGPASSWORD
              valueFrom: {secretKeyRef: {name: %s, key: password}}
          command: ["/bin/sh", "-ec"]
          args: ["mkdir -p /backup/%s && pg_dump -h platform-postgresql -U %s -d %s --no-owner -Fc -f /backup/%s/database.dump"]
          volumeMounts:
            - {name: backup, mountPath: /backup}
`, bundle.Spec.Workloads.PostgreSQLImage, dbSecret, id, dbUser, database, id)
	}
	volumeMount := ""
	volume := ""
	command := fmt.Sprintf("mkdir -p /backup/%s && echo service=%s > /backup/%s/marker", id, service, id)
	if pvc != "" {
		volumeMount = `
            - {name: data, mountPath: /data}`
		volume = fmt.Sprintf(`
        - name: data
          persistentVolumeClaim: {claimName: %s}`, pvc)
		command = fmt.Sprintf("mkdir -p /backup/%s && tar -C /data -czf /backup/%s/data.tar.gz .", id, id)
	}
	return fmt.Sprintf(`apiVersion: batch/v1
kind: Job
metadata: {name: %s, namespace: platform-system, annotations: {"platform.4so.io/job-owner": "lifecycle", "platform.4so.io/operation-id": %q, "platform.4so.io/job-name": %q}}
spec:
  backoffLimit: 1
  template:
    metadata: {labels: {app: platform-lifecycle}}
    spec:
      restartPolicy: Never%s
      nodeName: %q
      securityContext: {runAsUser: 0, runAsGroup: 0}
      containers:
        - name: data-backup
          image: %s
          securityContext: {allowPrivilegeEscalation: false}
          command: ["/bin/sh", "-ec"]
          args: [%q]
          volumeMounts:
            - {name: backup, mountPath: /backup}%s
      volumes:
        - name: backup
          hostPath: {path: %s, type: DirectoryOrCreate}%s
`, jobName, operationID, jobName, init, executionNode, bundle.Spec.Workloads.MaintenanceImage, command, volumeMount, filepath.Clean(backupRoot), volume)
}

func restoreJobManifest(service, id, jobName, operationID, backupRoot string, bundle bootstrap.BundleManifest, profileID, executionNode string, meta BackupMetadata) string {
	pvc := ""
	database := ""
	switch service {
	case "forgejo":
		pvc = "data-platform-forgejo-0"
		database = "forgejo"
	case "zot":
		pvc = "platform-zot-data"
	case "keycloak":
		database = "keycloak"
	}
	verifyCommand := restorePayloadStageCommand(id, meta)
	init := fmt.Sprintf(`
      initContainers:
        - name: verify-backup
          image: %s
          securityContext: {allowPrivilegeEscalation: false}
          command: ["/bin/sh", "-ec"]
          args: [%q]
          volumeMounts:
            - {name: backup, mountPath: /backup, readOnly: true}
            - {name: verified-backup, mountPath: /verified}
`, bundle.Spec.Workloads.MaintenanceImage, verifyCommand)
	if database != "" {
		dbUser, dbSecret := databaseCredentials(service, profileID)
		init += fmt.Sprintf(`        - name: database-restore
          image: %s
          env:
            - name: PGPASSWORD
              valueFrom: {secretKeyRef: {name: %s, key: password}}
          command: ["/bin/sh", "-ec"]
          args:
            - >-
              pg_restore -h platform-postgresql -U %s -d %s --clean --if-exists --no-owner --exit-on-error /verified/database.dump
          volumeMounts:
            - {name: verified-backup, mountPath: /verified, readOnly: true}
`, bundle.Spec.Workloads.PostgreSQLImage, dbSecret, dbUser, database)
	}
	volumeMount := ""
	volume := ""
	command := "true"
	if pvc != "" {
		volumeMount = `
            - {name: data, mountPath: /data}`
		volume = fmt.Sprintf(`
        - name: data
          persistentVolumeClaim: {claimName: %s}`, pvc)
		command = "find /data -mindepth 1 -maxdepth 1 -exec rm -rf {} + && tar -C /data -xzf /verified/data.tar.gz"
	}
	return fmt.Sprintf(`apiVersion: batch/v1
kind: Job
metadata: {name: %s, namespace: platform-system, annotations: {"platform.4so.io/job-owner": "lifecycle", "platform.4so.io/operation-id": %q, "platform.4so.io/job-name": %q}}
spec:
  backoffLimit: 1
  template:
    metadata: {labels: {app: platform-lifecycle}}
    spec:
      restartPolicy: Never%s
      nodeName: %q
      securityContext: {runAsUser: 0, runAsGroup: 0}
      containers:
        - name: data-restore
          image: %s
          securityContext: {allowPrivilegeEscalation: false}
          command: ["/bin/sh", "-ec"]
          args: [%q]
          volumeMounts:
            - {name: verified-backup, mountPath: /verified, readOnly: true}%s
      volumes:
        - name: backup
          hostPath: {path: %s, type: Directory}
        - name: verified-backup
          emptyDir: {}%s
`, jobName, operationID, jobName, init, executionNode, bundle.Spec.Workloads.MaintenanceImage, command, volumeMount, filepath.Clean(backupRoot), volume)
}

func restorePayloadStageCommand(id string, meta BackupMetadata) string {
	commands := []string{"set -eu", "umask 077", "mkdir -p /verified"}
	files := append([]BackupFile(nil), meta.Files...)
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	for _, file := range files {
		source := filepath.ToSlash(filepath.Join("/backup", id, file.Name))
		staged := filepath.ToSlash(filepath.Join("/verified", file.Name))
		digest := strings.TrimPrefix(file.SHA256, "sha256:")
		commands = append(commands,
			fmt.Sprintf("test -f %q && test ! -L %q", source, source),
			fmt.Sprintf("test \"$(wc -c < %q | tr -d ' ')\" = %q", source, fmt.Sprint(file.Size)),
			fmt.Sprintf("test \"$(sha256sum %q | cut -d ' ' -f1)\" = %q", source, digest),
			fmt.Sprintf("cat %q > %q", source, staged),
			fmt.Sprintf("test \"$(wc -c < %q | tr -d ' ')\" = %q", staged, fmt.Sprint(file.Size)),
			fmt.Sprintf("test \"$(sha256sum %q | cut -d ' ' -f1)\" = %q", staged, digest),
		)
	}
	return strings.Join(commands, " && ")
}

func databaseCredentials(service, profileID string) (string, string) {
	if profileID == "production-standard-ha" {
		switch service {
		case "forgejo":
			return "forgejo", "platform-forgejo-db"
		case "keycloak":
			return "keycloak", "platform-keycloak-db"
		}
	}
	return "platform", "platform-database"
}
