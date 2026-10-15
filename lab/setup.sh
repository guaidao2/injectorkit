#!/usr/bin/env bash
# Deploy the InjectorKit lab on the target box.
#
#   bash setup.sh            install and start everything
#   bash teardown.sh         stop it and undo the network change
#
# The lab is a web application with an SSRF endpoint and an LFI endpoint, plus
# the internal services those two are supposed to reach: a real Redis, and
# stand-ins for the metadata service, Docker, etcd, memcached, PHP-FPM and
# friends. Nothing here is hardened, and nothing here should be reachable from
# anywhere but the testing host.

set -euo pipefail

LAB=/opt/injectorkit-lab
PORT=8080
REQUIRED_FILES=(www/index.php www/fetch.php www/include.php www/redirect.php internal.py javalab/ProtoLab.java)

for relative in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$LAB/$relative" ]; then
        echo "missing $LAB/$relative - upload the lab directory first" >&2
        exit 1
    fi
done

echo "[1/6] layout"
mkdir -p "$LAB/logs"
if [ ! -f "$LAB/flag.txt" ]; then
    printf 'flag{injectorkit_lab_%s}\n' "$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')" > "$LAB/flag.txt"
fi
echo "  flag: $LAB/flag.txt"

echo "[2/6] apache on :$PORT"
# The metadata service owns 169.254.169.254:80, and Apache's default site would
# bind 0.0.0.0:80 and take it. Both changes are undone by teardown.sh.
a2dissite 000-default >/dev/null 2>&1 || true
if grep -qE '^Listen 80$' /etc/apache2/ports.conf; then
    sed -i 's|^Listen 80$|#Listen 80  # disabled by the injectorkit lab|' /etc/apache2/ports.conf
fi
cat > /etc/apache2/sites-available/injectorkit-lab.conf <<EOF
Listen $PORT
<VirtualHost *:$PORT>
    ServerName injectorkit-lab
    DocumentRoot $LAB/www
    DirectoryIndex index.php
    <Directory $LAB/www>
        AllowOverride None
        Require all granted
    </Directory>
    ErrorLog $LAB/logs/apache-error.log
    CustomLog $LAB/logs/apache-access.log combined
</VirtualHost>
EOF
a2enmod php8.4 >/dev/null 2>&1 || a2enmod php >/dev/null 2>&1 || true
a2ensite injectorkit-lab >/dev/null
apache2ctl configtest
systemctl restart apache2

echo "[3/6] redis on 127.0.0.1:6379"
# Modern Redis refuses `CONFIG SET dir` and `dbfilename` at run time unless they
# are explicitly enabled - a hardening that closes the classic write-a-file
# chain. The lab enables them so the chain can be exercised at all; on a target
# that has not, the tool's job is to say so rather than claim success.
if ! ss -lnt | grep -q '127.0.0.1:6379'; then
    redis-server --port 6379 --bind 127.0.0.1 --daemonize yes --save '' --appendonly no --dir /tmp \
        --enable-protected-configs local
fi
redis-cli -h 127.0.0.1 ping

echo "[4/6] internal services"
if [ -f "$LAB/internal.pid" ] && kill -0 "$(cat "$LAB/internal.pid")" 2>/dev/null; then
    kill "$(cat "$LAB/internal.pid")" 2>/dev/null || true
    sleep 0.5
fi
ip addr add 169.254.169.254/32 dev lo 2>/dev/null || true
nohup python3 "$LAB/internal.py" > "$LAB/logs/internal.log" 2>&1 &
echo $! > "$LAB/internal.pid"

# A real FastCGI listener on 9000, so the PHP-FPM chain has something that
# actually executes PHP rather than a stand-in that only knows how to say no.
if command -v php-cgi >/dev/null 2>&1; then
    if ! ss -lnt | grep -q '127.0.0.1:9000'; then
        nohup php-cgi -b 127.0.0.1:9000 > "$LAB/logs/php-cgi.log" 2>&1 &
        echo $! > "$LAB/phpcgi.pid"
    fi
    echo "  php-cgi on 127.0.0.1:9000"
else
    echo "  php-cgi not installed; 9000 stays closed (PHP-FPM chain cannot be exercised)"
fi
sleep 1
sed -n '1,12p' "$LAB/logs/internal.log"

# A JVM endpoint that hands its parameter straight to `new URL(...)` - the shape
# a pseudo-protocol bug takes in Java. There is no include and no file read in
# the application's own code, only a URL it was given, and the JVM decides what
# that URL opens: a local file, a module inside the JDK, or an archive it
# downloads from wherever the URL names.
if command -v javac >/dev/null 2>&1; then
    if ! ss -lnt | grep -q '127.0.0.1:9100'; then
        (cd "$LAB/javalab" && javac ProtoLab.java 2>/dev/null)
        nohup java -cp "$LAB/javalab" ProtoLab 9100 > "$LAB/logs/javalab.log" 2>&1 &
        echo $! > "$LAB/javalab.pid"
        sleep 2
    fi
    echo "  java lab on 0.0.0.0:9100 (jar:, jrt:, netdoc:, file:)"
else
    echo "  javac not installed; the Java lab is skipped (jar:/jrt: cannot be exercised)"
fi

echo "[5/6] checks"
for probe in "127.0.0.1:$PORT/fetch.php" "169.254.169.254/latest/meta-data/" "127.0.0.1:2375/version"; do
    printf '  %-42s ' "$probe"
    curl -s -m 3 -o /dev/null -w '%{http_code}\n' "http://$probe" || echo "unreachable"
done
printf '  %-42s ' "LFI read of the flag"
curl -s -m 3 "http://127.0.0.1:$PORT/include.php?file=$LAB/flag.txt" | tail -1
printf '  %-42s ' "gopher to redis"
curl -s -m 5 "http://127.0.0.1:$PORT/fetch.php?url=gopher%3A%2F%2F127.0.0.1%3A6379%2F_PING%250d%250a" | head -1
if command -v javac >/dev/null 2>&1; then
    printf '  %-42s ' "jrt: read of a JDK class"
    curl -s -m 5 -o /tmp/ik-jrt.bin -w '%{http_code} %{size_download} bytes\n' \
        "http://127.0.0.1:9100/fetch?url=jrt:/java.base/java/lang/String.class"
fi

echo "[6/6] done"
cat <<EOF

  web        http://<this-host>:$PORT/
  ssrf       http://<this-host>:$PORT/fetch.php?url=<url>
  lfi        http://<this-host>:$PORT/include.php?file=<path>
  redirect   http://<this-host>:$PORT/redirect.php?to=<url>
  java       http://<this-host>:9100/fetch?url=<url>   (jar:, jrt:, netdoc:)

  internal   redis 127.0.0.1:6379 (real)
             metadata 169.254.169.254:80, docker :2375, etcd :2379, kubelet :10255,
             elasticsearch :9200, consul :8500, admin panel :8899,
             memcached :11211, php-fpm stand-in :9000
EOF
