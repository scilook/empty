#!/usr/bin/env bash
set -euo pipefail

# vuln-patch-agent (patch-agent) 작동 예시 스크립트
#
# - 기본 설정(/var/lib, /var/log)은 권한이 필요할 수 있어, 이 스크립트는 로컬 작업 디렉터리에
#   DB/로그/출력을 생성하는 config.json을 자동으로 만듭니다.
# - 패치 단계는 안전하게 `--dry-run`으로 실행합니다(apt-get 실행 안 함).
#
# 선택 환경변수:
#   NVD_API_KEY=...         # NVD API 키(없어도 동작 시도하지만 rate-limit/차단 가능)
#   SKIP_SYNC=1             # NVD sync 단계 생략
#   SINCE_ISO=...           # NVD 증분 시작 시각(ISO8601, 예: 2026-05-11T00:00:00Z)
#   MAX_PAGES=1             # NVD에서 가져올 페이지 수(데모는 1 권장)
#   OVAL_FILE=/path/to.xml  # (선택) Ubuntu OVAL XML로 alias import
#   WORKDIR=...             # 산출물 디렉터리(기본: 현재 디렉터리/_vuln-patch-agent-demo)

WORKDIR="${WORKDIR:-$(pwd)/_vuln-patch-agent-demo}"
mkdir -p "$WORKDIR"

CONFIG="$WORKDIR/config.json"
DB="$WORKDIR/vuln_patch.db"
AUDIT="$WORKDIR/audit.log"
SCAN_OUT="$WORKDIR/scan.json"
PATCH_OUT="$WORKDIR/patch.json"
REPORT_OUT="$WORKDIR/report.json"

cat > "$CONFIG" <<EOF
{
  "db_path": "${DB}",
  "audit_log": "${AUDIT}",
  "scan_output": "${SCAN_OUT}",
  "report_output": "${REPORT_OUT}",
  "nvd_endpoint": "https://services.nvd.nist.gov/rest/json/cves/2.0",
  "results_per_page": 2000
}
EOF

# 1) 설치된 CLI가 있으면 그걸 쓰고, 없으면 repo 내 Python 엔트리포인트로 폴백합니다.
if command -v vuln-patch-agent >/dev/null 2>&1; then
  VPA=(vuln-patch-agent)
else
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
  LOCAL_PY="$REPO_ROOT/pkg/vuln-patch-agent_0.1.0/usr/lib/vuln-patch-agent/patch_agent.py"

  if [[ -f "$LOCAL_PY" ]]; then
    VPA=(python3 "$LOCAL_PY")
  else
    echo "ERROR: vuln-patch-agent를 PATH에서 찾지 못했고, 로컬 patch_agent.py도 없습니다." >&2
    echo "- PATH에 vuln-patch-agent를 설치하거나" >&2
    echo "- 이 repo 루트가 보존된 상태에서 스크립트를 실행하세요." >&2
    exit 1
  fi
fi

echo "Using: ${VPA[*]}"
echo "Workdir: $WORKDIR"

# 2) DB 초기화
"${VPA[@]}" --config "$CONFIG" init-db

# 3) (선택) NVD 동기화
if [[ "${SKIP_SYNC:-0}" != "1" ]]; then
  SINCE_ISO="${SINCE_ISO:-$(python3 - <<'PY'
import datetime as dt
print((dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)).replace(microsecond=0).isoformat().replace('+00:00', 'Z'))
PY
)}"
  MAX_PAGES="${MAX_PAGES:-1}"

  echo "Syncing NVD (since=$SINCE_ISO, max-pages=$MAX_PAGES) ..."
  if ! "${VPA[@]}" --config "$CONFIG" sync-nvd --since "$SINCE_ISO" --max-pages "$MAX_PAGES"; then
    echo "WARN: sync-nvd 실패(네트워크/레이트리밋/키 미설정 등). 스캔은 계속 진행합니다." >&2
  fi
fi

# 4) (선택) OVAL alias import
if [[ -n "${OVAL_FILE:-}" ]]; then
  echo "Importing OVAL aliases: $OVAL_FILE"
  "${VPA[@]}" --config "$CONFIG" import-oval --file "$OVAL_FILE"
fi

# 5) 스캔
echo "Scanning installed packages -> $SCAN_OUT"
"${VPA[@]}" --config "$CONFIG" scan --output "$SCAN_OUT"

# 6) 패치(드라이런)
echo "Patching (dry-run) -> $PATCH_OUT"
"${VPA[@]}" --config "$CONFIG" patch --dry-run --scan-file "$SCAN_OUT" --output "$PATCH_OUT"

# 7) 리포트 생성
echo "Generating report -> $REPORT_OUT"
"${VPA[@]}" --config "$CONFIG" report --output "$REPORT_OUT"

echo "Done. Artifacts written under: $WORKDIR"
ls -la "$WORKDIR"
