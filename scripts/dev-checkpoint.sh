#!/usr/bin/env bash
set -euo pipefail

state_dir="${DEV_CHECKPOINT_STATE_DIR:-.local-dev}"
queue_file="$state_dir/PUSH_QUEUE.json"
status_file="$state_dir/SESSION_STATE.json"
verify_cmd="${DEV_VERIFY_CMD:-}"
push_enabled="${DEV_PUSH:-0}"
push_timeout="${DEV_PUSH_TIMEOUT_SECONDS:-30}"
message=""

usage() {
  cat <<USAGE
Usage:
  scripts/dev-checkpoint.sh checkpoint [message]
  scripts/dev-checkpoint.sh status
  scripts/dev-checkpoint.sh mark-pushed

Environment:
  DEV_VERIFY_CMD='command'        verification command run before commit
  DEV_PUSH=1                      attempt checkpoint push after local commit
  DEV_PUSH_TIMEOUT_SECONDS=30     bounded push timeout
  DEV_CHECKPOINT_STATE_DIR=.local-dev
USAGE
}

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "$repo_root" ]]; then
  echo "dev-checkpoint: not inside a git repository" >&2
  exit 2
fi
cd "$repo_root"
mkdir -p "$state_dir"

json_state() {
  local push_state="$1" push_error="$2"
  local head upstream remote_url dirty ahead behind
  head="$(git rev-parse HEAD)"
  upstream="$(git rev-parse --verify refs/remotes/origin/main 2>/dev/null || true)"
  remote_url="$(git remote get-url origin 2>/dev/null || true)"
  dirty=false
  [[ -n "$(git status --porcelain --untracked-files=normal)" ]] && dirty=true
  ahead=0; behind=0
  if [[ -n "$upstream" ]]; then
    read -r behind ahead < <(git rev-list --left-right --count "$upstream...HEAD")
  fi
  python3 - "$status_file" "$head" "$upstream" "$remote_url" "$dirty" "$ahead" "$behind" "$push_state" "$push_error" <<'PY'
import json, pathlib, sys, datetime
path, head, upstream, remote, dirty, ahead, behind, state, error = sys.argv[1:]
data = {
    "authority": "LOCAL_GIT_CHECKPOINT_V1",
    "head": head,
    "originMain": upstream,
    "remoteUrl": remote,
    "dirty": dirty == "true",
    "ahead": int(ahead),
    "behind": int(behind),
    "pushState": state,
    "pushError": error or None,
    "updatedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
}
pathlib.Path(path).write_text(json.dumps(data, indent=2) + "\n")
PY
}

queue_append() {
  local commit="$1" error="$2"
  python3 - "$queue_file" "$commit" "$error" <<'PY'
import json, pathlib, sys, datetime
path = pathlib.Path(sys.argv[1]); commit, error = sys.argv[2:]
if path.exists():
    try: data = json.loads(path.read_text())
    except Exception: data = {}
else: data = {}
items = data.get("pending", [])
if not any(x.get("commit") == commit for x in items):
    items.append({"commit": commit, "lastError": error or None, "queuedAt": datetime.datetime.now(datetime.timezone.utc).isoformat()})
data = {"authority": "LOCAL_GIT_PUSH_QUEUE_V1", "pending": items}
path.write_text(json.dumps(data, indent=2) + "\n")
PY
}

queue_clear_reachable() {
  local pushed="$1"
  python3 - "$queue_file" "$pushed" <<'PY'
import json, pathlib, subprocess, sys
path=pathlib.Path(sys.argv[1]); pushed=sys.argv[2]
if not path.exists():
    raise SystemExit(0)
try: data=json.loads(path.read_text())
except Exception: raise SystemExit(0)
keep=[]
for row in data.get("pending", []):
    c=row.get("commit", "")
    ok=subprocess.run(["git","merge-base","--is-ancestor",c,pushed], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode==0 if c else False
    if not ok: keep.append(row)
data["pending"]=keep
path.write_text(json.dumps(data, indent=2)+"\n")
PY
}

cmd="${1:-status}"
case "$cmd" in
  status)
    json_state "$(python3 - "$status_file" <<'PY'
import json, pathlib, sys
p=pathlib.Path(sys.argv[1])
try: print(json.loads(p.read_text()).get('pushState','UNKNOWN'))
except Exception: print('UNKNOWN')
PY
)" ""
    cat "$status_file"
    [[ -f "$queue_file" ]] && cat "$queue_file"
    ;;
  checkpoint)
    shift || true
    message="${*:-checkpoint: local development wave}"
    if [[ -n "$verify_cmd" ]]; then
      echo "dev-checkpoint: verify: $verify_cmd"
      bash -lc "$verify_cmd"
    fi
    git add -A
    if git diff --cached --quiet; then
      echo "dev-checkpoint: no staged changes; preserving current HEAD"
    else
      git -c user.name="${DEV_GIT_USER_NAME:-4SO Sandbox Checkpoint}" \
          -c user.email="${DEV_GIT_USER_EMAIL:-checkpoint@4so.local}" \
          commit -m "$message"
    fi
    head="$(git rev-parse HEAD)"
    if [[ "$push_enabled" == "1" ]]; then
      remote_url="$(git remote get-url origin 2>/dev/null || true)"
      if [[ "$remote_url" != http* && "$remote_url" != git@github.com:* ]]; then
        err="origin is not a network Git remote; push deferred"
        queue_append "$head" "$err"
        json_state "PUSH_PENDING" "$err"
        echo "dev-checkpoint: $err"
        exit 0
      fi
      set +e
      output="$(timeout "$push_timeout" git push origin HEAD:main 2>&1)"
      rc=$?
      set -e
      if [[ $rc -eq 0 ]]; then
        queue_clear_reachable "$head"
        json_state "PUSHED" ""
        echo "$output"
      else
        err="${output:0:2000}"
        queue_append "$head" "$err"
        json_state "PUSH_PENDING" "$err"
        echo "dev-checkpoint: push failed/deferred; development may continue" >&2
        echo "$output" >&2
      fi
    else
      queue_append "$head" "push disabled for this checkpoint"
      json_state "PUSH_PENDING" "push disabled for this checkpoint"
    fi
    echo "dev-checkpoint: HEAD=$head"
    ;;
  mark-pushed)
    head="$(git rev-parse HEAD)"
    queue_clear_reachable "$head"
    json_state "PUSHED" ""
    echo "dev-checkpoint: marked reachable commits pushed through $head"
    ;;
  *) usage; exit 2 ;;
esac
