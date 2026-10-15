<?php
// Lab index: what this application exposes, for a human reading it.

declare(strict_types=1);
header('Content-Type: text/html; charset=utf-8');
?>
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>InjectorKit lab</title></head>
<body>
<h1>InjectorKit lab</h1>
<p>A deliberately vulnerable application. Not hardened, not for production.</p>
<h2>Endpoints</h2>
<ul>
    <li><code>/fetch.php?url=&lt;url&gt;</code> - fetches the URL server-side (SSRF).
        http, https, file, php, data and ftp go through the stream layer;
        gopher and dict are spoken over a raw socket, so a payload can drive
        whatever answers.</li>
    <li><code>/include.php?file=&lt;path&gt;</code> - includes the path (LFI),
        including <code>php://filter</code> and <code>phar://</code>.</li>
    <li><code>/redirect.php?to=&lt;url&gt;</code> - open redirect, for reaching a
        destination through a redirect.</li>
</ul>
<h2>Internal services</h2>
<p>Reachable only from this host: redis 6379, metadata 169.254.169.254:80,
docker 2375, etcd 2379, kubelet 10255, elasticsearch 9200, consul 8500,
admin panel 8899, memcached 11211, php-fpm stand-in 9000.</p>
</body>
</html>
