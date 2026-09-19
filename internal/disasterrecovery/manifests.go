package disasterrecovery

import (
	"fmt"
	"strings"

	"platform.4so.io/factory/internal/bootstrap"
	"platform.4so.io/factory/internal/installation"
)

func drBackupCommitJobName(run Run) string     { return "dr-backup-commit-" + shortID(run.ID) }
func drRestorePreflightJobName(run Run) string { return "dr-restore-preflight-" + shortID(run.ID) }
func drBackupJobName(component string, run Run) string {
	return "dr-backup-" + component + "-" + shortID(run.ID)
}
func drRestoreJobName(component string, run Run) string {
	return "dr-restore-" + component + "-" + shortID(run.ID)
}

func jobAnnotations(owner, operationID, name string) string {
	return fmt.Sprintf(`{"platform.4so.io/job-owner": %q, "platform.4so.io/operation-id": %q, "platform.4so.io/job-name": %q}`, owner, operationID, name)
}

func target(request installation.InstallRequest) (endpoint, bucket, secret string) {
	o := request.Services.ObjectStorage
	return o.URL, o.Bucket, strings.TrimPrefix(o.CredentialRef, "external-secret://platform-system/")
}

func commonEnv(request installation.InstallRequest, objectKey string) string {
	endpoint, bucket, secret := target(request)
	return fmt.Sprintf(`
          env:
            - {name: S3_ENDPOINT, value: %q}
            - {name: S3_BUCKET, value: %q}
            - {name: S3_OBJECT_KEY, value: %q}
          envFrom:
            - secretRef: {name: %q}`, endpoint, bucket, objectKey, secret)
}

func commonIntegrityEnv(request installation.InstallRequest, objectKey, checksumKey string) string {
	endpoint, bucket, secret := target(request)
	return fmt.Sprintf(`
          env:
            - {name: S3_ENDPOINT, value: %q}
            - {name: S3_BUCKET, value: %q}
            - {name: S3_OBJECT_KEY, value: %q}
            - {name: S3_CHECKSUM_KEY, value: %q}
          envFrom:
            - secretRef: {name: %q}`, endpoint, bucket, objectKey, checksumKey, secret)
}

func commonPrefixEnv(request installation.InstallRequest, prefix string) string {
	endpoint, bucket, secret := target(request)
	return fmt.Sprintf(`
          env:
            - {name: S3_ENDPOINT, value: %q}
            - {name: S3_BUCKET, value: %q}
            - {name: S3_PREFIX, value: %q}
          envFrom:
            - secretRef: {name: %q}`, endpoint, bucket, prefix, secret)
}

func backupCommitSuffix(request installation.InstallRequest) string {
	return "_complete-v2-" + request.ProfileID
}

func backupCommitManifest(run Run, request installation.InstallRequest, bundle bootstrap.BundleManifest) string {
	key := run.ObjectPrefix + "/" + backupCommitSuffix(request)
	command := `printf 'complete\\n' > /tmp/complete && aws --endpoint-url "$S3_ENDPOINT" s3 cp /tmp/complete "s3://$S3_BUCKET/$S3_OBJECT_KEY" --sse AES256`
	return fmt.Sprintf(`apiVersion: batch/v1
kind: Job
metadata: {name: %s, namespace: platform-system, annotations: %s}
spec:
  backoffLimit: 1
  template:
    metadata: {labels: {app: platform-disaster-recovery, component: commit}}
    spec:
      restartPolicy: Never
      containers:
        - name: commit
          image: %s
          securityContext:
            runAsUser: 0
            runAsGroup: 0
            allowPrivilegeEscalation: false
          command: ["/bin/sh","-ec"]
          args: [%q]%s
`, drBackupCommitJobName(run), jobAnnotations("disaster-recovery", run.ID, drBackupCommitJobName(run)), bundle.Spec.Workloads.MaintenanceImage, command, commonEnv(request, key))
}

func restorePreflightManifest(run Run, request installation.InstallRequest, bundle bootstrap.BundleManifest) string {
	marker := backupCommitSuffix(request)
	components := make([]string, 0, len(disasterRecoveryComponents))
	for _, component := range disasterRecoveryComponents {
		components = append(components, fmt.Sprintf("%q", component))
	}
	command := `aws --endpoint-url "$S3_ENDPOINT" s3api head-object --bucket "$S3_BUCKET" --key "$S3_PREFIX/` + marker + `" >/dev/null && ` +
		`for component in ` + strings.Join(components, " ") + `; do ` +
		`object="$S3_PREFIX/$component.tar.gz"; checksum="$S3_PREFIX/$component.sha256"; ` +
		`aws --endpoint-url "$S3_ENDPOINT" s3api head-object --bucket "$S3_BUCKET" --key "$object" >/dev/null && ` +
		`aws --endpoint-url "$S3_ENDPOINT" s3api head-object --bucket "$S3_BUCKET" --key "$checksum" >/dev/null && ` +
		`aws --endpoint-url "$S3_ENDPOINT" s3 cp "s3://$S3_BUCKET/$checksum" "/tmp/$component.sha256" && ` +
		`expected="$(tr -d '\r\n ' < "/tmp/$component.sha256")" && ` +
		`test "${#expected}" -eq 64 && case "$expected" in *[!0-9a-f]*) exit 1;; esac && ` +
		`aws --endpoint-url "$S3_ENDPOINT" s3 cp "s3://$S3_BUCKET/$object" "/tmp/$component.tar.gz" && ` +
		`sha256sum "/tmp/$component.tar.gz" > "/tmp/$component.actual" && ` +
		`actual="$(cut -d ' ' -f1 "/tmp/$component.actual")" && test "$actual" = "$expected" && ` +
		safeTarArchiveCommand("/tmp/$component.tar.gz") +
		`rm -f "/tmp/$component.tar.gz" "/tmp/$component.sha256" "/tmp/$component.actual"; done`
	return fmt.Sprintf(`apiVersion: batch/v1
kind: Job
metadata: {name: %s, namespace: platform-system, annotations: %s}
spec:
  backoffLimit: 0
  template:
    metadata: {labels: {app: platform-disaster-recovery, component: preflight}}
    spec:
      restartPolicy: Never
      containers:
        - name: preflight
          image: %s
          securityContext:
            runAsUser: 0
            runAsGroup: 0
            allowPrivilegeEscalation: false
          command: ["/bin/sh","-ec"]
          args: [%q]%s
`, drRestorePreflightJobName(run), jobAnnotations("disaster-recovery", run.ID, drRestorePreflightJobName(run)), bundle.Spec.Workloads.MaintenanceImage, command, commonPrefixEnv(request, run.ObjectPrefix))
}

func postgresqlCredentialVolumes(request installation.InstallRequest) (volumes, mounts string) {
	if request.ProfileID == "production-standard-ha" {
		return `
        - name: db-platform-secret
          secret: {secretName: platform-postgresql-app}
        - name: db-keycloak-secret
          secret: {secretName: platform-keycloak-db}
        - name: db-forgejo-secret
          secret: {secretName: platform-forgejo-db}`,
			`
            - {name: db-platform-secret, mountPath: /secrets/platform, readOnly: true}
            - {name: db-keycloak-secret, mountPath: /secrets/keycloak, readOnly: true}
            - {name: db-forgejo-secret, mountPath: /secrets/forgejo, readOnly: true}`
	}
	return `
        - name: db-platform-secret
          secret: {secretName: platform-database}`,
		`
            - {name: db-platform-secret, mountPath: /secrets/platform, readOnly: true}`
}

func postgresqlBackupCommand(request installation.InstallRequest) string {
	platformSecret := "/secrets/platform/password"
	keycloakSecret := platformSecret
	forgejoSecret := platformSecret
	keycloakUser := "platform"
	forgejoUser := "platform"
	if request.ProfileID == "production-standard-ha" {
		keycloakSecret = "/secrets/keycloak/password"
		forgejoSecret = "/secrets/forgejo/password"
		keycloakUser = "keycloak"
		forgejoUser = "forgejo"
	}
	return fmt.Sprintf(`mkdir -p /work && `+
		`PGPASSWORD="$(cat %s)" pg_dump --clean --if-exists --no-owner -h platform-postgresql -U platform -d platform_factory -f /work/platform_factory.sql && `+
		`gzip -c /work/platform_factory.sql > /work/platform_factory.sql.gz && `+
		`PGPASSWORD="$(cat %s)" pg_dump --clean --if-exists --no-owner -h platform-postgresql -U %s -d keycloak -f /work/keycloak.sql && `+
		`gzip -c /work/keycloak.sql > /work/keycloak.sql.gz && `+
		`PGPASSWORD="$(cat %s)" pg_dump --clean --if-exists --no-owner -h platform-postgresql -U %s -d forgejo -f /work/forgejo.sql && `+
		`gzip -c /work/forgejo.sql > /work/forgejo.sql.gz && `+
		`tar -C /work -czf /work/postgresql.tar.gz platform_factory.sql.gz keycloak.sql.gz forgejo.sql.gz`,
		platformSecret, keycloakSecret, keycloakUser, forgejoSecret, forgejoUser)
}

func postgresqlRestoreCommand(request installation.InstallRequest) string {
	platformSecret := "/secrets/platform/password"
	keycloakSecret := platformSecret
	forgejoSecret := platformSecret
	keycloakUser := "platform"
	forgejoUser := "platform"
	legacyFallback := `gunzip -c /tmp/postgresql.tar.gz > /tmp/postgresql-legacy.sql && PGPASSWORD="$(cat /secrets/platform/password)" psql -v ON_ERROR_STOP=1 -h platform-postgresql -U platform -d postgres -f /tmp/postgresql-legacy.sql`
	if request.ProfileID == "production-standard-ha" {
		keycloakSecret = "/secrets/keycloak/password"
		forgejoSecret = "/secrets/forgejo/password"
		keycloakUser = "keycloak"
		forgejoUser = "forgejo"
		legacyFallback = `echo "legacy HA PostgreSQL pg_dumpall backups are not safely restorable; create a new backup with this release" >&2; exit 1`
	}
	return fmt.Sprintf(`if tar -tzf /tmp/postgresql.tar.gz >/dev/null 2>&1; then `+
		`if ! (`+safeTarArchiveCommand("/tmp/postgresql.tar.gz")+`true); then echo "unsafe PostgreSQL backup archive" >&2; exit 1; fi; `+
		`mkdir -p /work && tar -C /work -xzf /tmp/postgresql.tar.gz && `+
		`test -s /work/platform_factory.sql.gz && test -s /work/keycloak.sql.gz && test -s /work/forgejo.sql.gz && `+
		`gunzip -c /work/platform_factory.sql.gz > /work/platform_factory.sql && PGPASSWORD="$(cat %s)" psql -v ON_ERROR_STOP=1 -h platform-postgresql -U platform -d platform_factory -f /work/platform_factory.sql && `+
		`gunzip -c /work/keycloak.sql.gz > /work/keycloak.sql && PGPASSWORD="$(cat %s)" psql -v ON_ERROR_STOP=1 -h platform-postgresql -U %s -d keycloak -f /work/keycloak.sql && `+
		`gunzip -c /work/forgejo.sql.gz > /work/forgejo.sql && PGPASSWORD="$(cat %s)" psql -v ON_ERROR_STOP=1 -h platform-postgresql -U %s -d forgejo -f /work/forgejo.sql; `+
		`else %s; fi`, platformSecret, keycloakSecret, keycloakUser, forgejoSecret, forgejoUser, legacyFallback)
}

func backupManifest(component string, run Run, request installation.InstallRequest, bundle bootstrap.BundleManifest, nodeName string) string {
	key := run.ObjectPrefix + "/" + component + ".tar.gz"
	command := ""
	archivePath := ""
	volumes := ""
	mounts := ""
	affinity := ""
	switch component {
	case "postgresql":
		command = postgresqlBackupCommand(request)
		archivePath = "/work/postgresql.tar.gz"
		volumes, mounts = postgresqlCredentialVolumes(request)
	case "platform-secrets":
		archivePath = "/tmp/platform-secrets.tar.gz"
		command = `test -s /platform-secrets/internal/forgejo-admin-password && test -s /platform-secrets/internal/identity-admin-password && test -s /platform-secrets/internal/identity-admin-email && test -s /platform-secrets/internal/session-secret && test -s /platform-secrets/internal/catalog-signing-key && test -s /platform-secrets/internal/argocd-observer-token && test -s /installer-authority/gitops-signing-key && test -s /platform-secrets/ingress/tls.crt && test -s /platform-secrets/ingress/tls.key && test -s /platform-secrets/ingress/ca.crt && mkdir -p /work/internal /work/ingress /work/installer && cp /platform-secrets/internal/forgejo-admin-password /work/internal/forgejo-admin-password && cp /platform-secrets/internal/identity-admin-password /work/internal/identity-admin-password && cp /platform-secrets/internal/identity-admin-email /work/internal/identity-admin-email && cp /platform-secrets/internal/session-secret /work/internal/session-secret && cp /platform-secrets/internal/catalog-signing-key /work/internal/catalog-signing-key && cp /platform-secrets/internal/argocd-observer-token /work/internal/argocd-observer-token && cp /installer-authority/gitops-signing-key /work/installer/gitops-signing-key && cp /platform-secrets/ingress/tls.crt /work/ingress/tls.crt && cp /platform-secrets/ingress/tls.key /work/ingress/tls.key && cp /platform-secrets/ingress/ca.crt /work/ingress/ca.crt && tar -C /work -czf /tmp/platform-secrets.tar.gz internal/forgejo-admin-password internal/identity-admin-password internal/identity-admin-email internal/session-secret internal/catalog-signing-key internal/argocd-observer-token installer/gitops-signing-key ingress/tls.crt ingress/tls.key ingress/ca.crt`
		volumes = `
        - name: internal-services
          secret: {secretName: platform-internal-services}
        - name: ingress-tls
          secret: {secretName: platform-ingress-tls}
        - name: installer-gitops-signing-key
          hostPath: {path: /var/lib/4so-platform-installer/secrets/gitops-signing-key, type: File}`
		mounts = `
            - {name: internal-services, mountPath: /platform-secrets/internal, readOnly: true}
            - {name: ingress-tls, mountPath: /platform-secrets/ingress, readOnly: true}
            - {name: installer-gitops-signing-key, mountPath: /installer-authority/gitops-signing-key, readOnly: true}`
		affinity = backupNodePlacement(nodeName)
	case "agent-pki":
		archivePath = "/tmp/agent-pki.tar.gz"
		command = `test -s /agent-pki/client-ca.crt && test -s /agent-pki/client-ca.key && test -s /agent-pki/tls.crt && test -s /agent-pki/tls.key && tar -C /agent-pki -czf /tmp/agent-pki.tar.gz client-ca.crt client-ca.key tls.crt tls.key`
		volumes = `
        - name: agent-pki
          secret: {secretName: platform-agent-mtls}`
		mounts = `
            - {name: agent-pki, mountPath: /agent-pki, readOnly: true}`
	case "forgejo":
		archivePath = "/tmp/forgejo.tar.gz"
		command = `tar -C /data -czf /tmp/forgejo.tar.gz .`
		affinity = backupNodePlacement(nodeName)
		volumes = `
        - name: data
          persistentVolumeClaim: {claimName: data-platform-forgejo-0}`
		mounts = `
            - {name: data, mountPath: /data, readOnly: true}`
	default:
		archivePath = "/tmp/zot.tar.gz"
		command = `tar -C /data -czf /tmp/zot.tar.gz .`
		affinity = backupNodePlacement(nodeName)
		volumes = `
        - name: data
          persistentVolumeClaim: {claimName: platform-zot-data}`
		mounts = `
            - {name: data, mountPath: /data, readOnly: true}`
	}
	checksumKey := run.ObjectPrefix + "/" + component + ".sha256"
	checksumPath := "/tmp/" + component + ".sha256"
	checksumFullPath := checksumPath + ".full"
	command += fmt.Sprintf(` && sha256sum %q > %q && cut -d ' ' -f1 %q > %q && test "$(wc -c < %q)" -ge 64 && aws --endpoint-url "$S3_ENDPOINT" s3 cp %q "s3://$S3_BUCKET/$S3_OBJECT_KEY" --sse AES256 && aws --endpoint-url "$S3_ENDPOINT" s3 cp %q "s3://$S3_BUCKET/$S3_CHECKSUM_KEY" --sse AES256`, archivePath, checksumFullPath, checksumFullPath, checksumPath, checksumPath, archivePath, checksumPath)
	return fmt.Sprintf(`apiVersion: batch/v1
kind: Job
metadata: {name: %s, namespace: platform-system, annotations: %s}
spec:
  backoffLimit: 1
  template:
    metadata: {labels: {app: platform-disaster-recovery, component: %s}}
    spec:%s
      restartPolicy: Never
      containers:
        - name: backup
          image: %s
          securityContext:
            runAsUser: 0
            runAsGroup: 0
            allowPrivilegeEscalation: false
          command: ["/bin/sh","-ec"]
          args: [%q]%s
          volumeMounts:%s
      volumes:%s
`, drBackupJobName(component, run), jobAnnotations("disaster-recovery", run.ID, drBackupJobName(component, run)), component, affinity, bundle.Spec.Workloads.MaintenanceImage, command, commonIntegrityEnv(request, key, checksumKey), mounts, volumes)
}

func backupNodePlacement(nodeName string) string {
	if strings.TrimSpace(nodeName) == "" {
		return ""
	}
	return fmt.Sprintf(`
      nodeName: %q`, strings.TrimSpace(nodeName))
}

func restoreTargetForManifest(run Run, namespace, name string) RestoreTargetIdentity {
	for _, target := range run.RestoreTargets {
		if target.Namespace == namespace && target.Name == name {
			return target
		}
	}
	return RestoreTargetIdentity{}
}

func bindRestoreIdentityExpectation(command, prefix string, target RestoreTargetIdentity) string {
	needle := fmt.Sprintf(`test -n "$%s_UID" && test -n "$%s_RV" &&`, prefix, prefix)
	replacement := needle + fmt.Sprintf(` test "$%s_UID" = %q && test "$%s_RV" = %q &&`, prefix, target.UID, prefix, target.ResourceVersion)
	return strings.Replace(command, needle, replacement, 1)
}

func safeTarArchiveCommand(archive string) string {
	list := archive + ".members"
	return fmt.Sprintf(`tar -tzf %q > %q && tar -tvzf %q 2>/dev/null | awk '$1 !~ /^[-d]/ {exit 1} $1 ~ /^-/ && (substr($1,4,1) ~ /[sS]/ || substr($1,7,1) ~ /[sS]/) {exit 1}' && while IFS= read -r entry; do case "$entry" in /*|../*|*/../*|*/..|..) echo "unsafe archive member" >&2; rm -f %q; exit 1;; esac; done < %q && rm -f %q && `, archive, list, archive, list, list, list)
}

func restoreManifest(component string, run Run, request installation.InstallRequest, bundle bootstrap.BundleManifest) string {
	key := run.ObjectPrefix + "/" + component + ".tar.gz"
	checksumKey := run.ObjectPrefix + "/" + component + ".sha256"
	archivePath := "/tmp/" + component + ".tar.gz"
	checksumPath := "/tmp/" + component + ".sha256"
	actualPath := "/tmp/" + component + ".actual"
	command := ""
	volumes := ""
	mounts := ""
	switch component {
	case "postgresql":
		command = postgresqlRestoreCommand(request)
		volumes, mounts = postgresqlCredentialVolumes(request)
	case "platform-secrets":
		command = safeTarArchiveCommand("/tmp/platform-secrets.tar.gz") + `mkdir -p /work && tar -C /work -xzf /tmp/platform-secrets.tar.gz && test -s /work/internal/forgejo-admin-password && test -s /work/internal/identity-admin-password && test -s /work/internal/identity-admin-email && test -s /work/internal/session-secret && test -s /work/internal/catalog-signing-key && test -s /work/internal/argocd-observer-token && test -s /work/installer/gitops-signing-key && test -s /work/ingress/tls.crt && test -s /work/ingress/tls.key && test -s /work/ingress/ca.crt && INTERNAL_UID="$(/host/kubectl --kubeconfig /host/kubeconfig -n platform-system get secret platform-internal-services -o jsonpath='{.metadata.uid}')" && INTERNAL_RV="$(/host/kubectl --kubeconfig /host/kubeconfig -n platform-system get secret platform-internal-services -o jsonpath='{.metadata.resourceVersion}')" && test -n "$INTERNAL_UID" && test -n "$INTERNAL_RV" && FORGEJO_PASSWORD_B64="$(base64 < /work/internal/forgejo-admin-password | tr -d '\n')" && IDENTITY_PASSWORD_B64="$(base64 < /work/internal/identity-admin-password | tr -d '\n')" && IDENTITY_EMAIL_B64="$(base64 < /work/internal/identity-admin-email | tr -d '\n')" && SESSION_B64="$(base64 < /work/internal/session-secret | tr -d '\n')" && CATALOG_B64="$(base64 < /work/internal/catalog-signing-key | tr -d '\n')" && ARGO_OBSERVER_B64="$(base64 < /work/internal/argocd-observer-token | tr -d '\n')" && GITOPS_B64="$(base64 < /work/installer/gitops-signing-key | tr -d '\n')" && INTERNAL_PATCH="$(printf '[{"op":"test","path":"/metadata/uid","value":"%s"},{"op":"test","path":"/metadata/resourceVersion","value":"%s"},{"op":"replace","path":"/data","value":{"forgejo-admin-password":"%s","identity-admin-password":"%s","identity-admin-email":"%s","session-secret":"%s","catalog-signing-key":"%s","argocd-observer-token":"%s","gitops-signing-key":"%s"}}]' "$INTERNAL_UID" "$INTERNAL_RV" "$FORGEJO_PASSWORD_B64" "$IDENTITY_PASSWORD_B64" "$IDENTITY_EMAIL_B64" "$SESSION_B64" "$CATALOG_B64" "$ARGO_OBSERVER_B64" "$GITOPS_B64")" && /host/kubectl --kubeconfig /host/kubeconfig -n platform-system patch secret/platform-internal-services --type=json -p "$INTERNAL_PATCH" && INGRESS_UID="$(/host/kubectl --kubeconfig /host/kubeconfig -n platform-system get secret platform-ingress-tls -o jsonpath='{.metadata.uid}')" && INGRESS_RV="$(/host/kubectl --kubeconfig /host/kubeconfig -n platform-system get secret platform-ingress-tls -o jsonpath='{.metadata.resourceVersion}')" && test -n "$INGRESS_UID" && test -n "$INGRESS_RV" && TLS_CRT_B64="$(base64 < /work/ingress/tls.crt | tr -d '\n')" && TLS_KEY_B64="$(base64 < /work/ingress/tls.key | tr -d '\n')" && CA_CRT_B64="$(base64 < /work/ingress/ca.crt | tr -d '\n')" && INGRESS_PATCH="$(printf '[{"op":"test","path":"/metadata/uid","value":"%s"},{"op":"test","path":"/metadata/resourceVersion","value":"%s"},{"op":"test","path":"/type","value":"kubernetes.io/tls"},{"op":"replace","path":"/data","value":{"tls.crt":"%s","tls.key":"%s","ca.crt":"%s"}}]' "$INGRESS_UID" "$INGRESS_RV" "$TLS_CRT_B64" "$TLS_KEY_B64" "$CA_CRT_B64")" && /host/kubectl --kubeconfig /host/kubeconfig -n platform-system patch secret/platform-ingress-tls --type=json -p "$INGRESS_PATCH" && GIT_UID="$(/host/kubectl --kubeconfig /host/kubeconfig -n platform-gitops get secret platform-internal-git -o jsonpath='{.metadata.uid}')" && GIT_RV="$(/host/kubectl --kubeconfig /host/kubeconfig -n platform-gitops get secret platform-internal-git -o jsonpath='{.metadata.resourceVersion}')" && test -n "$GIT_UID" && test -n "$GIT_RV" && GIT_PATCH="$(printf '[{"op":"test","path":"/metadata/uid","value":"%s"},{"op":"test","path":"/metadata/resourceVersion","value":"%s"},{"op":"add","path":"/data/password","value":"%s"}]' "$GIT_UID" "$GIT_RV" "$FORGEJO_PASSWORD_B64")" && /host/kubectl --kubeconfig /host/kubeconfig -n platform-gitops patch secret/platform-internal-git --type=json -p "$GIT_PATCH"`
		command = bindRestoreIdentityExpectation(command, "INTERNAL", restoreTargetForManifest(run, "platform-system", "platform-internal-services"))
		command = bindRestoreIdentityExpectation(command, "INGRESS", restoreTargetForManifest(run, "platform-system", "platform-ingress-tls"))
		command = bindRestoreIdentityExpectation(command, "GIT", restoreTargetForManifest(run, "platform-gitops", "platform-internal-git"))
		volumes = `
        - name: host-kubectl
          hostPath: {path: /var/lib/rancher/rke2/bin/kubectl, type: File}
        - name: host-kubeconfig
          hostPath: {path: /etc/rancher/rke2/rke2.yaml, type: File}`
		mounts = `
            - {name: host-kubectl, mountPath: /host/kubectl, readOnly: true}
            - {name: host-kubeconfig, mountPath: /host/kubeconfig, readOnly: true}`
	case "agent-pki":
		command = safeTarArchiveCommand("/tmp/agent-pki.tar.gz") + `mkdir -p /tmp/agent-pki && tar -C /tmp/agent-pki -xzf /tmp/agent-pki.tar.gz && test -s /tmp/agent-pki/client-ca.crt && test -s /tmp/agent-pki/client-ca.key && test -s /tmp/agent-pki/tls.crt && test -s /tmp/agent-pki/tls.key && AGENT_UID="$(/host/kubectl --kubeconfig /host/kubeconfig -n platform-system get secret platform-agent-mtls -o jsonpath='{.metadata.uid}')" && AGENT_RV="$(/host/kubectl --kubeconfig /host/kubeconfig -n platform-system get secret platform-agent-mtls -o jsonpath='{.metadata.resourceVersion}')" && test -n "$AGENT_UID" && test -n "$AGENT_RV" && CLIENT_CA_CRT_B64="$(base64 < /tmp/agent-pki/client-ca.crt | tr -d '\n')" && CLIENT_CA_KEY_B64="$(base64 < /tmp/agent-pki/client-ca.key | tr -d '\n')" && AGENT_TLS_CRT_B64="$(base64 < /tmp/agent-pki/tls.crt | tr -d '\n')" && AGENT_TLS_KEY_B64="$(base64 < /tmp/agent-pki/tls.key | tr -d '\n')" && AGENT_PATCH="$(printf '[{"op":"test","path":"/metadata/uid","value":"%s"},{"op":"test","path":"/metadata/resourceVersion","value":"%s"},{"op":"replace","path":"/data","value":{"client-ca.crt":"%s","client-ca.key":"%s","tls.crt":"%s","tls.key":"%s"}}]' "$AGENT_UID" "$AGENT_RV" "$CLIENT_CA_CRT_B64" "$CLIENT_CA_KEY_B64" "$AGENT_TLS_CRT_B64" "$AGENT_TLS_KEY_B64")" && /host/kubectl --kubeconfig /host/kubeconfig -n platform-system patch secret/platform-agent-mtls --type=json -p "$AGENT_PATCH"`
		command = bindRestoreIdentityExpectation(command, "AGENT", restoreTargetForManifest(run, "platform-system", "platform-agent-mtls"))
		volumes = `
        - name: host-kubectl
          hostPath: {path: /var/lib/rancher/rke2/bin/kubectl, type: File}
        - name: host-kubeconfig
          hostPath: {path: /etc/rancher/rke2/rke2.yaml, type: File}`
		mounts = `
            - {name: host-kubectl, mountPath: /host/kubectl, readOnly: true}
            - {name: host-kubeconfig, mountPath: /host/kubeconfig, readOnly: true}`
	case "forgejo":
		command = safeTarArchiveCommand("/tmp/forgejo.tar.gz") + `find /data -mindepth 1 -maxdepth 1 -exec rm -rf {} + && tar -C /data -xzf /tmp/forgejo.tar.gz`
		volumes = `
        - name: data
          persistentVolumeClaim: {claimName: data-platform-forgejo-0}`
		mounts = `
            - {name: data, mountPath: /data}`
	default:
		command = safeTarArchiveCommand("/tmp/zot.tar.gz") + `find /data -mindepth 1 -maxdepth 1 -exec rm -rf {} + && tar -C /data -xzf /tmp/zot.tar.gz`
		volumes = `
        - name: data
          persistentVolumeClaim: {claimName: platform-zot-data}`
		mounts = `
            - {name: data, mountPath: /data}`
	}
	verify := fmt.Sprintf(`aws --endpoint-url "$S3_ENDPOINT" s3 cp "s3://$S3_BUCKET/$S3_CHECKSUM_KEY" %q && expected="$(tr -d '\r\n ' < %q)" && test "${#expected}" -eq 64 && case "$expected" in *[!0-9a-f]*) exit 1;; esac && aws --endpoint-url "$S3_ENDPOINT" s3 cp "s3://$S3_BUCKET/$S3_OBJECT_KEY" %q && sha256sum %q > %q && actual="$(cut -d ' ' -f1 %q)" && test "$actual" = "$expected" && `, checksumPath, checksumPath, archivePath, archivePath, actualPath, actualPath)
	command = verify + command
	return fmt.Sprintf(`apiVersion: batch/v1
kind: Job
metadata: {name: %s, namespace: platform-system, annotations: %s}
spec:
  backoffLimit: 1
  template:
    metadata: {labels: {app: platform-disaster-recovery, component: %s}}
    spec:
      restartPolicy: Never
      containers:
        - name: restore
          image: %s
          securityContext:
            runAsUser: 0
            runAsGroup: 0
            allowPrivilegeEscalation: false
          command: ["/bin/sh","-ec"]
          args: [%q]%s
          volumeMounts:%s
      volumes:%s
`, drRestoreJobName(component, run), jobAnnotations("disaster-recovery", run.ID, drRestoreJobName(component, run)), component, bundle.Spec.Workloads.MaintenanceImage, command, commonIntegrityEnv(request, key, checksumKey), mounts, volumes)
}
