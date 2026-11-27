#!/usr/bin/env bash
# Re-record docs/assets/demo.gif against a real reader and card.
#
# Needs asciinema (pipx install asciinema) and agg
# (cargo install --git https://github.com/asciinema/agg).
#
#   bash docs/assets/record.sh
#
# The demo runs `mifarepy watch --count 2`, then `mifarepy read 1 --block 0`.
# Before starting, write some text to the card that ends the demo:
#
#   mifarepy write 1 0 --text "Hello, mifarepy!"
#
# Start with no card on the reader. When "Waiting for cards" appears, tap one
# card and lift it, then put the card with the text on the reader and leave it
# there. MIFAREPY sets the command to run (default: mifarepy on PATH).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
MIFAREPY="${MIFAREPY:-mifarepy}"

type_and_run() {
    # Fake-type "mifarepy ARGS", then run it for real.
    local shown="mifarepy $*"
    printf '\033[1;32m$\033[0m '
    for ((i = 0; i < ${#shown}; i++)); do
        printf '%s' "${shown:i:1}"
        sleep 0.04
    done
    sleep 0.4
    printf '\n'
    "$MIFAREPY" "$@"
}

if [[ "${MIFAREPY_DEMO_INNER:-}" == 1 ]]; then
    type_and_run watch --count 2
    sleep 1
    type_and_run read 1 --block 0
    sleep 2
    exit 0
fi

CAST="$(mktemp --suffix=.cast)"
MIFAREPY_DEMO_INNER=1 asciinema rec --overwrite --quiet --cols 64 --rows 9 \
    --idle-time-limit 1.5 --command "bash $0" "$CAST"

if ! grep -q 'Sector 1 (Key' "$CAST"; then
    echo "Demo did not read a card; not writing the GIF ($CAST kept)." >&2
    exit 1
fi
agg --font-size 20 --theme monokai --last-frame-duration 4 "$CAST" "$HERE/demo.gif"
rm -f "$CAST"
echo "Wrote $HERE/demo.gif"
