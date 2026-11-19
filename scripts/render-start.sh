#!/bin/sh
# Starts the bundled lab (optional) and the KAVACH console inside one container.
# Render supplies the public port in $PORT. The lab listens on loopback only, so it is reachable from the console
# (scan target 127.0.0.1) but not from the internet.
set -eu
APP="${APP_DIR:-/app}"
PORT="${PORT:-10000}"
DATA="${VAPT_DATA:-/data}"
mkdir -p "$DATA"
if [ "${VAPT_RUN_LAB:-1}" = "1" ] && [ -x "$APP/lab" ]; then
  ( "$APP/lab" 2>&1 | sed -u 's/^/[lab] /' ) &
  sleep 1
fi
exec "$APP/vapt" -addr "0.0.0.0:${PORT}" -data "$DATA"
