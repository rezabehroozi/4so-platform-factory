package bootstrap

import (
	"bytes"
	"context"
	"fmt"
	"strings"
)

const objectStorageProbeAuthority = "INSTALLER_OBJECT_STORAGE_READ_WRITE_PROBE_V1"

func objectStorageProbeManifest(run Run, bundle BundleManifest) (string, string, error) {
	if run.Request.ProfileID != "production-standard-ha" {
		return "", "", nil
	}
	object := run.Request.Services.ObjectStorage
	secretRef := strings.TrimPrefix(object.CredentialRef, "external-secret://platform-system/")
	if secretRef == object.CredentialRef || strings.TrimSpace(secretRef) == "" || strings.Contains(secretRef, "/") {
		return "", "", fmt.Errorf("object storage probe requires external-secret://platform-system/<name>")
	}
	prefix := strings.Trim(object.Prefix, "/")
	if prefix == "" {
		prefix = "4so-platform-factory"
	}
	suffix := strings.TrimPrefix(run.ID, "bootstrap-")
	if len(suffix) > 20 {
		suffix = suffix[:20]
	}
	jobName := "platform-s3-probe-" + suffix
	key := prefix + "/installer-probes/" + run.ID + ".txt"
	payload := objectStorageProbeAuthority + ":" + run.ID
	command := `set -eu; ` +
		`printf '%s\n' "$PROBE_PAYLOAD" > /tmp/source; ` +
		`cleanup(){ aws --endpoint-url "$S3_ENDPOINT" s3 rm "s3://$S3_BUCKET/$S3_OBJECT_KEY" >/dev/null 2>&1 || true; }; ` +
		`trap cleanup EXIT; ` +
		`aws --endpoint-url "$S3_ENDPOINT" s3 cp /tmp/source "s3://$S3_BUCKET/$S3_OBJECT_KEY" --sse AES256; ` +
		`aws --endpoint-url "$S3_ENDPOINT" s3 cp "s3://$S3_BUCKET/$S3_OBJECT_KEY" /tmp/readback; ` +
		`cmp -s /tmp/source /tmp/readback; ` +
		`aws --endpoint-url "$S3_ENDPOINT" s3 rm "s3://$S3_BUCKET/$S3_OBJECT_KEY"; ` +
		`trap - EXIT`
	manifest := fmt.Sprintf(`apiVersion: batch/v1
kind: Job
metadata:
  name: %s
  namespace: platform-system
  annotations:
    platform.4so.io/bootstrap-owner: %q
    platform.4so.io/probe-authority: %q
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 300
  template:
    metadata:
      labels: {app: platform-installer-s3-probe}
    spec:
      restartPolicy: Never
      containers:
        - name: probe
          image: %s
          securityContext:
            runAsUser: 0
            runAsGroup: 0
            allowPrivilegeEscalation: false
            capabilities: {drop: ["ALL"]}
          command: ["/bin/sh", "-ec"]
          args: [%q]
          env:
            - {name: S3_ENDPOINT, value: %q}
            - {name: S3_BUCKET, value: %q}
            - {name: S3_OBJECT_KEY, value: %q}
            - {name: PROBE_PAYLOAD, value: %q}
          envFrom:
            - secretRef: {name: %q}
`, jobName, bootstrapObjectOwnerValue, objectStorageProbeAuthority, bundle.Spec.Workloads.MaintenanceImage, command, object.URL, object.Bucket, key, payload, secretRef)
	return jobName, manifest, nil
}

func (r *Runner) verifyOffNodeBackup(ctx context.Context, run Run, bundle BundleManifest) error {
	if run.Request.ProfileID != "production-standard-ha" {
		return nil
	}
	jobName, manifest, err := objectStorageProbeManifest(run, bundle)
	if err != nil {
		return err
	}
	kubectl := "/var/lib/rancher/rke2/bin/kubectl"
	// The probe owns its exact job name. Deleting an interrupted prior attempt
	// is safe because the object key is run-scoped and the probe itself is
	// write/read/delete idempotent with a best-effort EXIT cleanup trap.
	_ = r.system.Run(ctx, kubectl, []string{"--kubeconfig", "/etc/rancher/rke2/rke2.yaml", "-n", "platform-system", "delete", "job", jobName, "--ignore-not-found=true", "--wait=true"}, nil)
	if err = r.system.RunInput(ctx, kubectl, []string{"--kubeconfig", "/etc/rancher/rke2/rke2.yaml", "apply", "-f", "-"}, nil, bytes.NewBufferString(manifest)); err != nil {
		return fmt.Errorf("create credentialed object-storage probe: %w", err)
	}
	if err = r.system.Run(ctx, kubectl, []string{"--kubeconfig", "/etc/rancher/rke2/rke2.yaml", "-n", "platform-system", "wait", "--for=condition=complete", "job/" + jobName, "--timeout=2m"}, nil); err != nil {
		logs, _ := r.system.Output(ctx, kubectl, []string{"--kubeconfig", "/etc/rancher/rke2/rke2.yaml", "-n", "platform-system", "logs", "job/" + jobName, "--tail=80"}, nil)
		return fmt.Errorf("credentialed object-storage write/read/delete probe failed: %w: %s", err, strings.TrimSpace(string(logs)))
	}
	if err = r.system.Run(ctx, kubectl, []string{"--kubeconfig", "/etc/rancher/rke2/rke2.yaml", "-n", "platform-system", "delete", "job", jobName, "--ignore-not-found=true", "--wait=true"}, nil); err != nil {
		return fmt.Errorf("remove successful object-storage probe job: %w", err)
	}
	return nil
}
