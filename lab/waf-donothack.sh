#!/usr/bin/env bash
# Put donothack in front of the lab and report what it is doing.
#
#   bash waf-donothack.sh            PHP lab  8090 -> the lab's port
#   bash waf-donothack.sh 9100       Java lab 8090 -> 9100
#   bash waf-donothack.sh stop       take it down
#
# donothack is a separate download (guaidao2/donothack releases) - unpack it and
# point DNH at the directory. The lab does not fetch it for you.
#
# Its rule set is the acceptance baseline for this project: a payload that gets
# through these rules is a payload worth having, and one that does not is a
# result to report rather than a bug to hide.

set -uo pipefail

DNH=${DNH:-/opt/donothack/donothack_1.3.4_linux_amd64}
HERE=$(cd "$(dirname "$0")" && pwd)
# The upstream is whichever side of the lab you want in front of the filter: the
# PHP application by default, or the Java one when its port is named. The argument
# is still what the usage at the top of this file promises - an earlier edit here
# replaced it with the lab's own port and left the usage telling people to pass
# 9100, which then silently put the filter in front of the PHP side instead.
UPSTREAM_PORT=${1:-${IK_PORT:-18080}}
LISTEN_PORT=8090

if [ ! -x "$DNH/donothack" ]; then
    echo "donothack not found at $DNH (set DNH=... to point at it)" >&2
    exit 1
fi

stop() {
    local pid
    pid=$(ss -lntp 2>/dev/null | grep ":$LISTEN_PORT" | grep -oP 'pid=\K[0-9]+' | head -1)
    if [ -n "$pid" ]; then
        kill "$pid"
        echo "stopped donothack (pid $pid)"
    else
        echo "nothing listening on $LISTEN_PORT"
    fi
}

if [ "${1:-}" = "stop" ]; then
    stop
    exit 0
fi

stop
sleep 1

# The port is the only thing that differs between the two sides, so the template
# is edited in place rather than kept in two copies that drift apart.
sed "s|url: \"http://127.0.0.1:8080\"|url: \"http://127.0.0.1:$UPSTREAM_PORT\"|" \
    "$HERE/donothack.yaml" > "$DNH/iklab.yaml"

cd "$DNH" || exit 1
nohup ./donothack -c iklab.yaml > /tmp/donothack.log 2>&1 &
sleep 3

echo "--- listening ---"
ss -lnt | grep -E ":($LISTEN_PORT|$UPSTREAM_PORT)"
echo "--- mode ---"
grep -oE 'engine_mode=[a-z]+|profile=[a-z]+' /tmp/donothack.log | head -3

echo "--- is it filtering? ---"
printf '  %-40s ' "a clean request"
curl -s -m 5 -o /dev/null -w '%{http_code}\n' "http://127.0.0.1:$LISTEN_PORT/" || true
printf '  %-40s ' "a php wrapper"
curl -s -m 5 -o /dev/null -w '%{http_code}\n' \
    "http://127.0.0.1:$LISTEN_PORT/?file=php://filter/convert.base64-encode/resource=index.php" || true

cat <<EOF

  through it   http://<this-host>:$LISTEN_PORT/
  upstream     http://127.0.0.1:$UPSTREAM_PORT
  decisions    /tmp/donothack.log   (rule_id, category, and what matched)
  rules        $DNH/rules

EOF
