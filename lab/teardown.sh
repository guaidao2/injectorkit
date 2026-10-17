#!/usr/bin/env bash
# Stop the lab and undo what setup.sh changed outside /opt/injectorkit-lab.
# Uploaded files and the flag stay; pass --purge to remove them too.

set -uo pipefail

LAB=/opt/injectorkit-lab

echo "[1/4] internal services"
if [ -f "$LAB/internal.pid" ]; then
    kill "$(cat "$LAB/internal.pid")" 2>/dev/null || true
    rm -f "$LAB/internal.pid"
fi
if [ -f "$LAB/phpcgi.pid" ]; then
    kill "$(cat "$LAB/phpcgi.pid")" 2>/dev/null || true
    rm -f "$LAB/phpcgi.pid"
fi
if [ -f "$LAB/javalab.pid" ]; then
    kill "$(cat "$LAB/javalab.pid")" 2>/dev/null || true
    rm -f "$LAB/javalab.pid"
fi
ip addr del 169.254.169.254/32 dev lo 2>/dev/null || true

echo "[2/4] redis"
redis-cli -h 127.0.0.1 shutdown nosave 2>/dev/null || true

echo "[3/4] apache"
# setup.sh writes its vhost into 000-default.conf, so that is the one that has to
# go. Disabling the old `injectorkit-lab` name did nothing except leave the lab
# listening on its port: the file that name refers to has not been written since
# 0.1.0, and "the port is still taken after teardown" is the same defect as a
# stale vhost keeping 8080 alive.
a2dissite 000-default >/dev/null 2>&1 || true
rm -f /etc/apache2/sites-available/000-default.conf
rm -f /etc/apache2/sites-available/injectorkit-lab.conf \
      /etc/apache2/sites-enabled/injectorkit-lab.conf
if grep -qE '^#Listen 80 ' /etc/apache2/ports.conf; then
    sed -i 's|^#Listen 80 .*|Listen 80|' /etc/apache2/ports.conf
fi
apache2ctl configtest >/dev/null 2>&1 && systemctl restart apache2 || true

echo "[4/4] files"
if [ "${1:-}" = "--purge" ]; then
    rm -rf "$LAB"
    echo "  removed $LAB"
else
    echo "  kept $LAB"
fi
