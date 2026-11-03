#!/usr/bin/env bash
# Re-record docs/assets/demo.gif against a real reader and card.
#
# Needs asciinema (pipx install asciinema) and agg
# (cargo install --git https://github.com/asciinema/agg).
#
#   docs/assets/record.sh [port]
#
# Remove the card first, start this script, then tap the card when the demo
# says "Waiting for a card...".
set -euo pipefail

PORT="${1:-/dev/ttyUSB0}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PYTHON="${PYTHON:-python}"

if [[ "${MIFAREPY_DEMO_INNER:-}" == 1 ]]; then
    # Runs inside the recording: fake-type the command, then run it for real.
    cmd="python demo.py $PORT"
    printf '\033[1;32m$\033[0m '
    for ((i = 0; i < ${#cmd}; i++)); do
        printf '%s' "${cmd:i:1}"
        sleep 0.04
    done
    sleep 0.4
    printf '\n'
    "$PYTHON" "$HERE/demo.py" "$PORT"
    sleep 2
    exit 0
fi

CAST="$(mktemp --suffix=.cast)"
MIFAREPY_DEMO_INNER=1 asciinema rec --overwrite --quiet --cols 64 --rows 8 \
    --idle-time-limit 1.5 --command "$0 $PORT" "$CAST"

if ! grep -q 'Card UID:' "$CAST"; then
    echo "Demo did not read a card; not writing the GIF ($CAST kept)." >&2
    exit 1
fi
agg --font-size 20 --theme monokai --last-frame-duration 3 "$CAST" "$HERE/demo.gif"
rm -f "$CAST"
echo "Wrote $HERE/demo.gif"
