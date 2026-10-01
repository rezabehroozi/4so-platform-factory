#!/usr/bin/env bash
set -euo pipefail

AUTHORITY="INSTALLER_MANUAL_ENTRYPOINT_V1"
CONTINUATION_AUTHORITY="INSTALLER_MANUAL_CONTINUATION_ENTRYPOINT_V1"
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PLATFORMCTL="${ROOT_DIR}/bin/linux-amd64/platformctl"
INSTALLER="${ROOT_DIR}/bin/linux-amd64/platform-installer"

usage() {
  cat <<'EOF'
4SO Platform Factory guided manual installation

Usage:
  sudo bash install.sh preflight --bundle-dir DIR [--release-artifact RELEASE.zip] [installer options...]
  sudo bash install.sh plan      --bundle-dir DIR [--release-artifact RELEASE.zip] [installer options...]
  sudo bash install.sh install   --bundle-dir DIR [--release-artifact RELEASE.zip] --enable-execution --confirmation DEPLOY [installer options...]
  sudo bash install.sh status    [--state FILE] [--root /]
  sudo bash install.sh verify    [--state FILE] [--root /]
  sudo bash install.sh recover   --confirmation RECOVER [--state FILE] [--root /]
  sudo bash install.sh rollback  --confirmation ROLLBACK [--state FILE] [--root /]

The exact release ZIP can be omitted only when PLATFORM_FACTORY_RELEASE_ARTIFACT
is set or when the ZIP sits beside this extracted release directory with the
same basename. The script never downloads moving upstream content and never
creates a second installation engine; it delegates to platformctl
installer-manual.

Common install options:
  --enable-execution
  --listen HOST:PORT
  --tls-cert FILE --tls-key FILE
  --allow-downgrade
  --out-spec FILE

Safe default:
  Installer listens on 127.0.0.1:9080. The result prints an SSH local-forward
  command for remote browser access without exposing Installer on the network.

Continuation:
  status/verify/recover/rollback read the durable host-deployment authority.
  They do not require the original bundle or release ZIP again. recover and
  rollback retain the canonical explicit confirmation fences.
EOF
}

mode="${1:-}"
case "${mode}" in
  help|-h|--help|"")
    usage
    exit 0
    ;;
  preflight|plan|install|status|verify|recover|rollback)
    shift
    ;;
  *)
    echo "ERROR unsupported mode: ${mode}" >&2
    usage >&2
    exit 2
    ;;
esac

if [[ "${EUID}" -ne 0 ]]; then
  echo "ERROR ${AUTHORITY}: live manual installation must run as root; rerun with sudo" >&2
  exit 2
fi

if [[ ! -f "${PLATFORMCTL}" || -L "${PLATFORMCTL}" || ! -x "${PLATFORMCTL}" ]]; then
  echo "ERROR ${AUTHORITY}: required packaged executable is missing/non-regular/non-executable: ${PLATFORMCTL}" >&2
  exit 2
fi

case "${mode}" in
  status|verify|recover|rollback)
    echo "${AUTHORITY} continuationAuthority=${CONTINUATION_AUTHORITY} mode=${mode} continuation=true" >&2
    exec "${PLATFORMCTL}" installer-manual "${mode}" "$@"
    ;;
esac

if [[ ! -f "${INSTALLER}" || -L "${INSTALLER}" || ! -x "${INSTALLER}" ]]; then
  echo "ERROR ${AUTHORITY}: required packaged executable is missing/non-regular/non-executable: ${INSTALLER}" >&2
  exit 2
fi

bundle_dir=""
release_artifact="${PLATFORM_FACTORY_RELEASE_ARTIFACT:-}"
declare -a passthrough=()
while (($#)); do
  case "$1" in
    --bundle-dir)
      [[ $# -ge 2 ]] || { echo "ERROR --bundle-dir requires a value" >&2; exit 2; }
      bundle_dir="$2"
      shift 2
      ;;
    --release-artifact)
      [[ $# -ge 2 ]] || { echo "ERROR --release-artifact requires a value" >&2; exit 2; }
      release_artifact="$2"
      shift 2
      ;;
    *)
      passthrough+=("$1")
      shift
      ;;
  esac
done

if [[ -z "${bundle_dir}" ]]; then
  echo "ERROR ${AUTHORITY}: --bundle-dir is required" >&2
  exit 2
fi
if [[ ! -d "${bundle_dir}" || -L "${bundle_dir}" ]]; then
  echo "ERROR ${AUTHORITY}: bundle directory must be a real non-symlink directory: ${bundle_dir}" >&2
  exit 2
fi

if [[ -z "${release_artifact}" ]]; then
  adjacent="$(dirname -- "${ROOT_DIR}")/$(basename -- "${ROOT_DIR}").zip"
  if [[ -f "${adjacent}" && ! -L "${adjacent}" ]]; then
    release_artifact="${adjacent}"
  fi
fi
if [[ -z "${release_artifact}" ]]; then
  echo "ERROR ${AUTHORITY}: exact release ZIP is required; pass --release-artifact or set PLATFORM_FACTORY_RELEASE_ARTIFACT" >&2
  exit 2
fi
if [[ ! -f "${release_artifact}" || -L "${release_artifact}" ]]; then
  echo "ERROR ${AUTHORITY}: release artifact must be a regular non-symlink file: ${release_artifact}" >&2
  exit 2
fi

echo "${AUTHORITY} mode=${mode} bundle=${bundle_dir} release=${release_artifact}" >&2
exec "${PLATFORMCTL}" installer-manual "${mode}" \
  --installer-binary "${INSTALLER}" \
  --bundle-dir "${bundle_dir}" \
  --release-artifact "${release_artifact}" \
  "${passthrough[@]}"
