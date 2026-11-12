#!/usr/bin/env bash
# Reproduce GHSA-qx49-fqc8-xw99 locally against several releases of the Python SDK.
# Everything runs on 127.0.0.1 with a lab-only fake secret. Needs Python 3.10+ and network
# access to PyPI for the first run.
set -euo pipefail
cd "$(dirname "$0")"
VERSIONS=${VERSIONS:-"1.29.1 1.30.0 2.3.0"}
OUT=../results/results-$(date +%Y%m%d-%H%M%S).jsonl
: > "$OUT"
for v in $VERSIONS; do
  if [ ! -x ".venv-$v/bin/python" ]; then
    python3 -m venv ".venv-$v"
    ".venv-$v/bin/pip" install -q "mcp==$v"
  fi
  for opts in "" "--construct-in-main" "--issuer"; do
    ".venv-$v/bin/python" run_case.py $opts 2>/dev/null | tail -1 >> "$OUT"
  done
done
python3 - "$OUT" <<'EOF'
import json, sys
print(f"{'mcp':8} {'issuer=':8} {'built in':11} {'warning shown':24} secret reached rogue AS")
for line in open(sys.argv[1]):
    d = json.loads(line)
    if "skipped" in d:
        continue
    print(f"{d['mcp']:8} {('yes' if d['issuer_passed'] else 'no'):8} {d['constructed_in']:11} "
          f"{(','.join(d['warnings_shown']) or '-'):24} {'YES' if d['secret_reached_rogue_as'] else 'no'}")
print(f"\nraw results: {sys.argv[1]}")
EOF
