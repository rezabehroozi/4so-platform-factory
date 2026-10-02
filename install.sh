#!/usr/bin/env bash
set -euo pipefail

AUTHORITY="INSTALLER_MANUAL_ENTRYPOINT_V1"
CONTINUATION_AUTHORITY="INSTALLER_MANUAL_CONTINUATION_ENTRYPOINT_V1"
ACTIONABLE_AUTHORITY="INSTALLER_MANUAL_ACTIONABLE_ENTRYPOINT_V1"
DOCTOR_HANDOFF_AUTHORITY="INSTALLER_MANUAL_EXACT_NEXT_COMMAND_V1"
HOST_RUNTIME_DOCTOR_AUTHORITY="INSTALLER_MANUAL_HOST_RUNTIME_DOCTOR_V1"
MACHINE_NEXT_ACTION_AUTHORITY="INSTALLER_MANUAL_MACHINE_NEXT_ACTION_V1"
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PLATFORMCTL="${ROOT_DIR}/bin/linux-amd64/platformctl"
INSTALLER="${ROOT_DIR}/bin/linux-amd64/platform-installer"
DEFAULT_BOOTSTRAP_TOKEN_FILE="/var/lib/4so-platform-installer/bootstrap-token"
EXPECTED_VERSION="$(tr -d '\r\n' < "${ROOT_DIR}/VERSION" 2>/dev/null || true)"

usage() {
  cat <<'EOF'
4SO Platform Factory guided manual installation

Usage:
  bash install.sh doctor    [--bundle-dir DIR] [--release-artifact RELEASE.zip]
  sudo bash install.sh preflight [--bundle-dir DIR] [--release-artifact RELEASE.zip] [installer options...]
  sudo bash install.sh plan      [--bundle-dir DIR] [--release-artifact RELEASE.zip] [installer options...]
  sudo bash install.sh install   [--bundle-dir DIR] [--release-artifact RELEASE.zip] --enable-execution --confirmation DEPLOY [installer options...]
  sudo bash install.sh status           [--state FILE] [--root /]
  sudo bash install.sh verify           [--state FILE] [--root /]
  [sudo] bash install.sh bootstrap-status [--installer-url URL] [--token-file FILE] [--ca-file FILE]
  [sudo] bash install.sh resume           --confirmation RESUME [--installer-url URL] [--token-file FILE] [--ca-file FILE]
  [sudo] bash install.sh reset            --confirmation RESET [--installer-url URL] [--token-file FILE] [--ca-file FILE]
  [sudo] bash install.sh reset-resume     --confirmation RESUME-RESET [--installer-url URL] [--token-file FILE] [--ca-file FILE]
  sudo bash install.sh recover          --confirmation RECOVER [--state FILE] [--root /]
  sudo bash install.sh rollback         --confirmation ROLLBACK [--state FILE] [--root /]

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
  bootstrap-status/resume/reset/reset-resume read the live Bootstrap Installer
  durable authority. Resume and journaled reset mutations are status-first and
  require their explicit confirmation tokens. None of these modes require the
  original bundle or release ZIP again; no lost-response mutation is auto-replayed.
  The default loopback handoff reads the private
  /var/lib/4so-platform-installer/bootstrap-token and therefore requires sudo.
  Remote/custom authenticated continuation does not require local root when
  --token-file, PLATFORM_INSTALLER_TOKEN_FILE or PLATFORM_INSTALLER_TOKEN is
  supplied; --installer-url and --ca-file remain explicit transport inputs.
EOF
}

mode="${1:-}"
case "${mode}" in
  help|-h|--help|"")
    usage
    exit 0
    ;;
  doctor|preflight|plan|install|status|verify|bootstrap-status|resume|reset|reset-resume|recover|rollback)
    shift
    ;;
  *)
    echo "ERROR unsupported mode: ${mode}" >&2
    usage >&2
    exit 2
    ;;
esac

case "${mode}" in
  bootstrap-status|resume|reset|reset-resume)
    if [[ ! -f "${PLATFORMCTL}" || -L "${PLATFORMCTL}" || ! -x "${PLATFORMCTL}" ]]; then
      echo "ERROR ${AUTHORITY}: Bootstrap Installer continuation requires packaged platformctl: ${PLATFORMCTL}" >&2
      exit 2
    fi
    declare -a access_args=("$@")
    access_has_url=false
    access_has_token_file=false
    access_token_file=""
    for ((i=0; i<${#access_args[@]}; i++)); do
      case "${access_args[i]}" in
        --installer-url|--token-file|--ca-file|--confirmation)
          if [[ $((i + 1)) -ge ${#access_args[@]} || -z "${access_args[i+1]}" ]]; then
            echo "ERROR ${AUTHORITY}: ${access_args[i]} requires a value" >&2
            exit 2
          fi
          ;;
        --installer-url=|--token-file=|--ca-file=|--confirmation=)
          echo "ERROR ${AUTHORITY}: ${access_args[i]%%=*} requires a value" >&2
          exit 2
          ;;
      esac
      case "${access_args[i]}" in
        --installer-url)
          access_has_url=true
          ;;
        --installer-url=*)
          access_has_url=true
          ;;
        --token-file)
          access_has_token_file=true
          access_token_file="${access_args[i+1]}"
          ;;
        --token-file=*)
          access_has_token_file=true
          access_token_file="${access_args[i]#--token-file=}"
          ;;
      esac
    done
    if [[ "${access_has_token_file}" != true && -z "${PLATFORM_INSTALLER_TOKEN:-}" ]]; then
      access_token_file="${PLATFORM_INSTALLER_TOKEN_FILE:-${DEFAULT_BOOTSTRAP_TOKEN_FILE}}"
    fi
    if [[ "${EUID}" -ne 0 && -z "${PLATFORM_INSTALLER_TOKEN:-}" && "${access_token_file}" == "${DEFAULT_BOOTSTRAP_TOKEN_FILE}" ]]; then
      echo "ERROR ${AUTHORITY}: default Bootstrap Installer continuation reads ${DEFAULT_BOOTSTRAP_TOKEN_FILE}; rerun with sudo or provide a readable custom --token-file / PLATFORM_INSTALLER_TOKEN_FILE / PLATFORM_INSTALLER_TOKEN" >&2
      exit 2
    fi
    if [[ "${access_has_url}" != true ]]; then
      access_args=(--installer-url "${PLATFORM_INSTALLER_URL:-http://127.0.0.1:9080}" "${access_args[@]}")
    fi
    if [[ "${access_has_token_file}" != true && -z "${PLATFORM_INSTALLER_TOKEN:-}" ]]; then
      access_args=(--token-file "${access_token_file}" "${access_args[@]}")
    fi
    access_command="${mode}"
    [[ "${mode}" == "bootstrap-status" ]] && access_command="run-status"
    echo "${AUTHORITY} continuationAuthority=${CONTINUATION_AUTHORITY} mode=${mode} bootstrapContinuation=true" >&2
    exec "${PLATFORMCTL}" installer-access "${access_command}" "${access_args[@]}"
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
declare -a passthrough=()
while (($#)); do
  case "$1" in
    --bundle-dir)
      [[ $# -ge 2 && -n "$2" ]] || { echo "ERROR --bundle-dir requires a value" >&2; exit 2; }
      bundle_dir="$2"
      shift 2
      ;;
    --bundle-dir=*)
      bundle_dir="${1#--bundle-dir=}"
      [[ -n "${bundle_dir}" ]] || { echo "ERROR --bundle-dir requires a value" >&2; exit 2; }
      shift
      ;;
    --release-artifact)
      [[ $# -ge 2 && -n "$2" ]] || { echo "ERROR --release-artifact requires a value" >&2; exit 2; }
      release_artifact="$2"
      shift 2
      ;;
    --release-artifact=*)
      release_artifact="${1#--release-artifact=}"
      [[ -n "${release_artifact}" ]] || { echo "ERROR --release-artifact requires a value" >&2; exit 2; }
      shift
      ;;
    *)
      passthrough+=("$1")
      shift
      ;;
  esac
done

if [[ "${mode}" == "install" ]]; then
  execution_requested=false
  deploy_confirmed=false
  for ((i=0; i<${#passthrough[@]}; i++)); do
    case "${passthrough[i]}" in
      --enable-execution|--enable-execution=true|--enable-execution=TRUE|--enable-execution=True|--enable-execution=1)
        execution_requested=true
        ;;
    esac
    if [[ "${passthrough[i]}" == "--confirmation" && $((i + 1)) -lt ${#passthrough[@]} && "${passthrough[i+1]}" == "DEPLOY" ]]; then
      deploy_confirmed=true
    elif [[ "${passthrough[i]}" == "--confirmation=DEPLOY" ]]; then
      deploy_confirmed=true
    fi
  done
  if [[ "${execution_requested}" != true ]]; then
    echo "ERROR ${ACTIONABLE_AUTHORITY}: normal install requires --enable-execution so the Browser Installer is actionable after host deployment" >&2
    exit 2
  fi
  if [[ "${deploy_confirmed}" != true ]]; then
    echo "ERROR ${ACTIONABLE_AUTHORITY}: install requires explicit --confirmation DEPLOY" >&2
    exit 2
  fi
fi

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
  platformctl_runnable=false
  installer_runnable=false
  host_platform_ready=false
  bundle_inputs_ready=false
  release_artifact_ready=false
  host_os="$(uname -s 2>/dev/null || true)"
  host_arch="$(uname -m 2>/dev/null || true)"
  if [[ "${host_os}" == "Linux" && ("${host_arch}" == "x86_64" || "${host_arch}" == "amd64") ]]; then
    host_platform_ready=true
  else
    ready=false
  fi
  [[ -f "${PLATFORMCTL}" && ! -L "${PLATFORMCTL}" && -x "${PLATFORMCTL}" ]] && platformctl_ready=true || ready=false
  [[ -f "${INSTALLER}" && ! -L "${INSTALLER}" && -x "${INSTALLER}" ]] && installer_ready=true || ready=false
  if [[ "${host_platform_ready}" == true && "${platformctl_ready}" == true ]]; then
    platformctl_version="$("${PLATFORMCTL}" --version 2>/dev/null | tr -d '\r\n' || true)"
    [[ -n "${EXPECTED_VERSION}" && "${platformctl_version}" == *"${EXPECTED_VERSION}"* ]] && platformctl_runnable=true || ready=false
  fi
  if [[ "${host_platform_ready}" == true && "${installer_ready}" == true ]]; then
    installer_version="$("${INSTALLER}" --version 2>/dev/null | tr -d '\r\n' || true)"
    [[ -n "${EXPECTED_VERSION}" && "${installer_version}" == *"${EXPECTED_VERSION}"* ]] && installer_runnable=true || ready=false
  fi
  [[ -n "${bundle_dir}" && -d "${bundle_dir}" && ! -L "${bundle_dir}" && -r "${bundle_dir}/bundle.json" && -r "${bundle_dir}/bundle.lock.json" ]] && bundle_inputs_ready=true || ready=false
  [[ -n "${release_artifact}" && -f "${release_artifact}" && ! -L "${release_artifact}" && -r "${release_artifact}" ]] && release_artifact_ready=true || ready=false
  printf '%s\n' \
    "authority=INSTALLER_MANUAL_DOCTOR_V1" \
    "handoffAuthority=${DOCTOR_HANDOFF_AUTHORITY}" \
    "hostRuntimeAuthority=${HOST_RUNTIME_DOCTOR_AUTHORITY}" \
    "machineNextActionAuthority=${MACHINE_NEXT_ACTION_AUTHORITY}" \
    "readyForPreflight=${ready}" \
    "bundleAdmissionVerified=false" \
    "hostPlatformReady=${host_platform_ready}" \
    "hostOS=${host_os}" \
    "hostArch=${host_arch}" \
    "expectedVersion=${EXPECTED_VERSION}" \
    "platformctlReady=${platformctl_ready}" \
    "platformctlRunnable=${platformctl_runnable}" \
    "installerReady=${installer_ready}" \
    "installerRunnable=${installer_runnable}" \
    "bundleInputsReady=${bundle_inputs_ready}" \
    "releaseArtifactReady=${release_artifact_ready}"
  printf 'platformctl=%q\ninstaller=%q\nbundleDirectory=%q\nreleaseArtifact=%q\n' \
    "${PLATFORMCTL}" "${INSTALLER}" "${bundle_dir}" "${release_artifact}"
  if [[ "${ready}" == true ]]; then
    printf '%s\n' "nextActionCode=RUN_PREFLIGHT"
    printf '%s\n' "nextAction=copy nextCommand exactly; canonical bundle/release admission happens during preflight"
    printf 'nextCommand=sudo bash %q preflight --bundle-dir %q --release-artifact %q' \
      "${ROOT_DIR}/install.sh" "${bundle_dir}" "${release_artifact}"
    if (("${#passthrough[@]}")); then
      printf ' %q' "${passthrough[@]}"
    fi
    printf '\n'
  else
    printf '%s\n' "nextActionCode=RESOLVE_DOCTOR_BLOCKERS"
    printf '%s\n' "nextAction=resolve the false readiness fields above (including host platform and binary runtime/version compatibility), then rerun this doctor command; do not start preflight yet"
    printf '%s\n' "nextCommand="
  fi
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

print_exact_next_command() {
  local next_mode="$1"
  shift
  local -a command=(sudo bash "${ROOT_DIR}/install.sh" "${next_mode}" --bundle-dir "${bundle_dir}" --release-artifact "${release_artifact}" "$@")
  printf '%s nextMode=%s nextCommand=' "${DOCTOR_HANDOFF_AUTHORITY}" "${next_mode}" >&2
  printf '%q ' "${command[@]}" >&2
  printf '\n' >&2
}

declare -a manual_args=(installer-manual "${mode}" --installer-binary "${INSTALLER}" --bundle-dir "${bundle_dir}" --release-artifact "${release_artifact}" "${passthrough[@]}")
declare -a handoff_passthrough=()
for ((i=0; i<${#passthrough[@]}; i++)); do
  case "${passthrough[i]}" in
    --out-spec)
      if [[ $((i + 1)) -lt ${#passthrough[@]} ]]; then
        ((i+=1))
      fi
      ;;
    --out-spec=*)
      ;;
    *)
      handoff_passthrough+=("${passthrough[i]}")
      ;;
  esac
done
echo "${AUTHORITY} mode=${mode} bundle=${bundle_dir} release=${release_artifact}" >&2

if [[ "${mode}" == "preflight" ]]; then
  if "${PLATFORMCTL}" "${manual_args[@]}"; then
    print_exact_next_command plan "${handoff_passthrough[@]}"
    exit 0
  else
    rc=$?
    exit "${rc}"
  fi
fi

if [[ "${mode}" == "plan" ]]; then
  if "${PLATFORMCTL}" "${manual_args[@]}"; then
    declare -a install_passthrough=()
    for ((i=0; i<${#handoff_passthrough[@]}; i++)); do
      case "${handoff_passthrough[i]}" in
        --enable-execution|--enable-execution=*)
          ;;
        --confirmation)
          if [[ $((i + 1)) -lt ${#handoff_passthrough[@]} ]]; then
            ((i+=1))
          fi
          ;;
        --confirmation=*)
          ;;
        *)
          install_passthrough+=("${handoff_passthrough[i]}")
          ;;
      esac
    done
    install_passthrough+=(--enable-execution --confirmation DEPLOY)
    print_exact_next_command install "${install_passthrough[@]}"
    exit 0
  else
    rc=$?
    exit "${rc}"
  fi
fi

exec "${PLATFORMCTL}" "${manual_args[@]}"
