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
  bash install.sh doctor    [--bundle-dir DIR] [--release-artifact RELEASE.zip]
  sudo bash install.sh preflight [--bundle-dir DIR] [--release-artifact RELEASE.zip] [installer options...]
  sudo bash install.sh plan      [--bundle-dir DIR] [--release-artifact RELEASE.zip] [installer options...]
  sudo bash install.sh install   [--bundle-dir DIR] [--release-artifact RELEASE.zip] --enable-execution --confirmation DEPLOY [installer options...]
  sudo bash install.sh status    [--state FILE] [--root /]
  sudo bash install.sh verify    [--state FILE] [--root /]
  sudo bash install.sh recover   --confirmation RECOVER [--state FILE] [--root /]
  sudo bash install.sh rollback  --confirmation ROLLBACK [--state FILE] [--root /]

The bundle directory can be supplied with --bundle-dir or PLATFORM_INSTALLER_BUNDLE_DIR.
When omitted, the entrypoint safely checks the extracted release's bundle/,
appliance-bundle/, its parent bundle/, then /opt/4so-platform-factory/bundle.
The exact release ZIP can be omitted when PLATFORM_FACTORY_RELEASE_ARTIFACT
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

Doctor:
  doctor is read-only and does not require root. It reports input readiness for
  packaged binaries, bundle files and the exact release ZIP. It does not claim
  bundle admission; canonical digest/exact-release verification starts at preflight.

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
  doctor|preflight|plan|install|status|verify|recover|rollback)
    shift
    ;;
  *)
    echo "ERROR unsupported mode: ${mode}" >&2
    usage >&2
    exit 2
    ;;
esac

case "${mode}" in
  status|verify|recover|rollback)
    if [[ "${EUID}" -ne 0 ]]; then
      echo "ERROR ${AUTHORITY}: installer continuation must run as root; rerun with sudo" >&2
      exit 2
    fi
    if [[ ! -f "${PLATFORMCTL}" || -L "${PLATFORMCTL}" || ! -x "${PLATFORMCTL}" ]]; then
      echo "ERROR ${AUTHORITY}: continuation requires packaged platformctl: ${PLATFORMCTL}" >&2
      exit 2
    fi
    echo "${AUTHORITY} continuationAuthority=${CONTINUATION_AUTHORITY} mode=${mode} continuation=true" >&2
    exec "${PLATFORMCTL}" installer-manual "${mode}" "$@"
    ;;
esac

bundle_dir="${PLATFORM_INSTALLER_BUNDLE_DIR:-}"
release_artifact="${PLATFORM_FACTORY_RELEASE_ARTIFACT:-}"

discover_bundle_dir() {
  local candidate
  for candidate in     "${ROOT_DIR}/bundle"     "${ROOT_DIR}/appliance-bundle"     "$(dirname -- "${ROOT_DIR}")/bundle"     "/opt/4so-platform-factory/bundle"; do
    if [[ -d "${candidate}" && ! -L "${candidate}" && -f "${candidate}/bundle.json" && -f "${candidate}/bundle.lock.json" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  return 1
}

discover_release_artifact() {
  local adjacent
  adjacent="$(dirname -- "${ROOT_DIR}")/$(basename -- "${ROOT_DIR}").zip"
  if [[ -f "${adjacent}" && ! -L "${adjacent}" ]]; then
    printf '%s\n' "${adjacent}"
    return 0
  fi
  return 1
}

json_escape() {
  local value="${1-}"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//
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
  bundle_dir="$(discover_bundle_dir || true)"
fi
if [[ -z "${release_artifact}" ]]; then
  release_artifact="$(discover_release_artifact || true)"
fi

if [[ "${mode}" == "doctor" ]]; then
  ready=true
  platformctl_ready=false
  installer_ready=false
  bundle_inputs_ready=false
  release_artifact_ready=false
  [[ -f "${PLATFORMCTL}" && ! -L "${PLATFORMCTL}" && -x "${PLATFORMCTL}" ]] && platformctl_ready=true || ready=false
  [[ -f "${INSTALLER}" && ! -L "${INSTALLER}" && -x "${INSTALLER}" ]] && installer_ready=true || ready=false
  [[ -n "${bundle_dir}" && -d "${bundle_dir}" && ! -L "${bundle_dir}" && -f "${bundle_dir}/bundle.json" && -f "${bundle_dir}/bundle.lock.json" ]] && bundle_inputs_ready=true || ready=false
  [[ -n "${release_artifact}" && -f "${release_artifact}" && ! -L "${release_artifact}" ]] && release_artifact_ready=true || ready=false
  printf '{"authority":"INSTALLER_MANUAL_DOCTOR_V1","readyForPreflight":%s,"bundleAdmissionVerified":false,"platformctlReady":%s,"installerReady":%s,"bundleInputsReady":%s,"releaseArtifactReady":%s,"platformctl":"%s","installer":"%s","bundleDirectory":"%s","releaseArtifact":"%s","nextAction":"%s"}\n' \
    "${ready}" "${platformctl_ready}" "${installer_ready}" "${bundle_inputs_ready}" "${release_artifact_ready}" \
    "$(json_escape "${PLATFORMCTL}")" "$(json_escape "${INSTALLER}")" "$(json_escape "${bundle_dir}")" "$(json_escape "${release_artifact}")" \
    "$(json_escape "when readyForPreflight=true, run sudo bash install.sh preflight; canonical bundle/release admission happens there")"
  [[ "${ready}" == true ]]
  exit
fi

if [[ ! -f "${PLATFORMCTL}" || -L "${PLATFORMCTL}" || ! -x "${PLATFORMCTL}" ]]; then
  echo "ERROR ${AUTHORITY}: required packaged executable is missing/non-regular/non-executable: ${PLATFORMCTL}" >&2
  exit 2
fi
if [[ ! -f "${INSTALLER}" || -L "${INSTALLER}" || ! -x "${INSTALLER}" ]]; then
  echo "ERROR ${AUTHORITY}: required packaged executable is missing/non-regular/non-executable: ${INSTALLER}" >&2
  exit 2
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "ERROR ${AUTHORITY}: live manual installation must run as root; rerun with sudo" >&2
  exit 2
fi

if [[ -z "${bundle_dir}" ]]; then
  echo "ERROR ${AUTHORITY}: no bundle input directory discovered; pass --bundle-dir or set PLATFORM_INSTALLER_BUNDLE_DIR, then let canonical preflight verify admission" >&2
  exit 2
fi
if [[ ! -d "${bundle_dir}" || -L "${bundle_dir}" ]]; then
  echo "ERROR ${AUTHORITY}: bundle directory must be a real non-symlink directory: ${bundle_dir}" >&2
  exit 2
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
\n'/\\n}"
  value="${value//
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
  bundle_dir="$(discover_bundle_dir || true)"
fi
if [[ -z "${release_artifact}" ]]; then
  release_artifact="$(discover_release_artifact || true)"
fi

if [[ "${mode}" == "doctor" ]]; then
  ready=true
  [[ -f "${PLATFORMCTL}" && ! -L "${PLATFORMCTL}" && -x "${PLATFORMCTL}" ]] || ready=false
  [[ -f "${INSTALLER}" && ! -L "${INSTALLER}" && -x "${INSTALLER}" ]] || ready=false
  [[ -n "${bundle_dir}" && -d "${bundle_dir}" && ! -L "${bundle_dir}" && -f "${bundle_dir}/bundle.json" && -f "${bundle_dir}/bundle.lock.json" ]] || ready=false
  [[ -n "${release_artifact}" && -f "${release_artifact}" && ! -L "${release_artifact}" ]] || ready=false
  printf '{"authority":"INSTALLER_MANUAL_DOCTOR_V1","ready":%s,"platformctl":"%s","installer":"%s","bundleDirectory":"%s","releaseArtifact":"%s"}\n'     "${ready}" "${PLATFORMCTL}" "${INSTALLER}" "${bundle_dir}" "${release_artifact}"
  [[ "${ready}" == true ]]
  exit
fi

if [[ ! -f "${PLATFORMCTL}" || -L "${PLATFORMCTL}" || ! -x "${PLATFORMCTL}" ]]; then
  echo "ERROR ${AUTHORITY}: required packaged executable is missing/non-regular/non-executable: ${PLATFORMCTL}" >&2
  exit 2
fi
if [[ ! -f "${INSTALLER}" || -L "${INSTALLER}" || ! -x "${INSTALLER}" ]]; then
  echo "ERROR ${AUTHORITY}: required packaged executable is missing/non-regular/non-executable: ${INSTALLER}" >&2
  exit 2
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "ERROR ${AUTHORITY}: live manual installation must run as root; rerun with sudo" >&2
  exit 2
fi

if [[ -z "${bundle_dir}" ]]; then
  echo "ERROR ${AUTHORITY}: no verified bundle directory discovered; pass --bundle-dir or set PLATFORM_INSTALLER_BUNDLE_DIR" >&2
  exit 2
fi
if [[ ! -d "${bundle_dir}" || -L "${bundle_dir}" ]]; then
  echo "ERROR ${AUTHORITY}: bundle directory must be a real non-symlink directory: ${bundle_dir}" >&2
  exit 2
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
\r'/\\r}"
  value="${value//
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
  bundle_dir="$(discover_bundle_dir || true)"
fi
if [[ -z "${release_artifact}" ]]; then
  release_artifact="$(discover_release_artifact || true)"
fi

if [[ "${mode}" == "doctor" ]]; then
  ready=true
  [[ -f "${PLATFORMCTL}" && ! -L "${PLATFORMCTL}" && -x "${PLATFORMCTL}" ]] || ready=false
  [[ -f "${INSTALLER}" && ! -L "${INSTALLER}" && -x "${INSTALLER}" ]] || ready=false
  [[ -n "${bundle_dir}" && -d "${bundle_dir}" && ! -L "${bundle_dir}" && -f "${bundle_dir}/bundle.json" && -f "${bundle_dir}/bundle.lock.json" ]] || ready=false
  [[ -n "${release_artifact}" && -f "${release_artifact}" && ! -L "${release_artifact}" ]] || ready=false
  printf '{"authority":"INSTALLER_MANUAL_DOCTOR_V1","ready":%s,"platformctl":"%s","installer":"%s","bundleDirectory":"%s","releaseArtifact":"%s"}\n'     "${ready}" "${PLATFORMCTL}" "${INSTALLER}" "${bundle_dir}" "${release_artifact}"
  [[ "${ready}" == true ]]
  exit
fi

if [[ ! -f "${PLATFORMCTL}" || -L "${PLATFORMCTL}" || ! -x "${PLATFORMCTL}" ]]; then
  echo "ERROR ${AUTHORITY}: required packaged executable is missing/non-regular/non-executable: ${PLATFORMCTL}" >&2
  exit 2
fi
if [[ ! -f "${INSTALLER}" || -L "${INSTALLER}" || ! -x "${INSTALLER}" ]]; then
  echo "ERROR ${AUTHORITY}: required packaged executable is missing/non-regular/non-executable: ${INSTALLER}" >&2
  exit 2
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "ERROR ${AUTHORITY}: live manual installation must run as root; rerun with sudo" >&2
  exit 2
fi

if [[ -z "${bundle_dir}" ]]; then
  echo "ERROR ${AUTHORITY}: no verified bundle directory discovered; pass --bundle-dir or set PLATFORM_INSTALLER_BUNDLE_DIR" >&2
  exit 2
fi
if [[ ! -d "${bundle_dir}" || -L "${bundle_dir}" ]]; then
  echo "ERROR ${AUTHORITY}: bundle directory must be a real non-symlink directory: ${bundle_dir}" >&2
  exit 2
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
\t'/\\t}"
  printf '%s' "${value}"
}

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
  bundle_dir="$(discover_bundle_dir || true)"
fi
if [[ -z "${release_artifact}" ]]; then
  release_artifact="$(discover_release_artifact || true)"
fi

if [[ "${mode}" == "doctor" ]]; then
  ready=true
  [[ -f "${PLATFORMCTL}" && ! -L "${PLATFORMCTL}" && -x "${PLATFORMCTL}" ]] || ready=false
  [[ -f "${INSTALLER}" && ! -L "${INSTALLER}" && -x "${INSTALLER}" ]] || ready=false
  [[ -n "${bundle_dir}" && -d "${bundle_dir}" && ! -L "${bundle_dir}" && -f "${bundle_dir}/bundle.json" && -f "${bundle_dir}/bundle.lock.json" ]] || ready=false
  [[ -n "${release_artifact}" && -f "${release_artifact}" && ! -L "${release_artifact}" ]] || ready=false
  printf '{"authority":"INSTALLER_MANUAL_DOCTOR_V1","ready":%s,"platformctl":"%s","installer":"%s","bundleDirectory":"%s","releaseArtifact":"%s"}\n'     "${ready}" "${PLATFORMCTL}" "${INSTALLER}" "${bundle_dir}" "${release_artifact}"
  [[ "${ready}" == true ]]
  exit
fi

if [[ ! -f "${PLATFORMCTL}" || -L "${PLATFORMCTL}" || ! -x "${PLATFORMCTL}" ]]; then
  echo "ERROR ${AUTHORITY}: required packaged executable is missing/non-regular/non-executable: ${PLATFORMCTL}" >&2
  exit 2
fi
if [[ ! -f "${INSTALLER}" || -L "${INSTALLER}" || ! -x "${INSTALLER}" ]]; then
  echo "ERROR ${AUTHORITY}: required packaged executable is missing/non-regular/non-executable: ${INSTALLER}" >&2
  exit 2
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "ERROR ${AUTHORITY}: live manual installation must run as root; rerun with sudo" >&2
  exit 2
fi

if [[ -z "${bundle_dir}" ]]; then
  echo "ERROR ${AUTHORITY}: no verified bundle directory discovered; pass --bundle-dir or set PLATFORM_INSTALLER_BUNDLE_DIR" >&2
  exit 2
fi
if [[ ! -d "${bundle_dir}" || -L "${bundle_dir}" ]]; then
  echo "ERROR ${AUTHORITY}: bundle directory must be a real non-symlink directory: ${bundle_dir}" >&2
  exit 2
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
