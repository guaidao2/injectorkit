<?php
// SSRF where the destination is assembled from two parameters.
//
// Plenty of applications take a host and a path separately, and a payload aimed
// at either one alone is a URL fragment that never gets fetched. This endpoint
// is the shape that makes that testable.

declare(strict_types=1);

$host = isset($_GET['host']) ? (string) $_GET['host'] : '';
$path = isset($_GET['path']) ? (string) $_GET['path'] : '';
header('Content-Type: text/plain; charset=utf-8');

if ($host === '') {
    echo "usage: /fetch_split.php?host=<host>&path=<path>\n";
    exit;
}

// The host parameter carries an authority and nothing else. A payload aimed at
// it alone is therefore useless here: the destination only exists once the two
// parameters are combined, which is the shape being tested.
if (strpos($host, '://') !== false) {
    $authority = substr($host, strpos($host, '://') + 3);
} else {
    $authority = $host;
}
if (strpbrk($authority, '/?') !== false) {
    echo "invalid host: a bare host:port is expected\n";
    exit;
}

$target = (strpos($host, '://') !== false ? $host : 'http://' . $host) . $path;

if (str_starts_with($target, 'gopher://')) {
    $parts = parse_url($target);
    $fp = @fsockopen($parts['host'] ?? '127.0.0.1', (int) ($parts['port'] ?? 70), $errno, $errstr, 3.0);
    if (!$fp) {
        echo "gopher connect failed: {$errstr}\n";
        exit;
    }
    $at = strpos($target, '_');
    $payload = $at !== false ? urldecode(substr($target, $at + 1)) : '';
    if ($payload !== '') {
        fwrite($fp, $payload);
        fflush($fp);
    }
    stream_set_timeout($fp, 3);
    $out = '';
    while (!feof($fp)) {
        $chunk = fread($fp, 4096);
        if ($chunk === false || $chunk === '') {
            break;
        }
        $out .= $chunk;
    }
    fclose($fp);
    echo $out;
    exit;
}

$context = stream_context_create([
    'http' => ['timeout' => 5, 'follow_location' => 0, 'ignore_errors' => true],
    'ssl' => ['verify_peer' => false, 'verify_peer_name' => false],
]);
$data = @file_get_contents($target, false, $context);
echo $data === false ? "fetch failed for {$target}\n" : $data;
