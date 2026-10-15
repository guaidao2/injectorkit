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
a2dissite injectorkit-lab >/dev/null 2>&1 || true
rm -f /etc/apache2/sites-available/injectorkit-lab.conf
if grep -qE '^#Listen 80 ' /etc/apache2/ports.conf; then
    sed -i 's|^#Listen 80 .*|Listen 80|' /etc/apache2/ports.conf
    a2ensite 000-default >/dev/null 2>&1 || true
fi
apache2ctl configtest >/dev/null 2>&1 && systemctl restart apache2 || true

echo "[4/4] files"
if [ "${1:-}" = "--purge" ]; then
    rm -rf "$LAB"
    echo "  removed $LAB"
else
    echo "  kept $LAB"
fi
