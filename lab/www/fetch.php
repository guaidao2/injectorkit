<?php
// SSRF endpoint: fetches whatever the caller hands it.
//
// This mirrors the endpoint shape that actually appears in the wild, including
// the part that matters for exploitation: the application hands the URL to a
// low-level client, so a `gopher://` URL can speak a protocol of the caller's
// choosing to whatever answers on the other side.
//
// PHP 8.4 registers no gopher or dict wrapper and this box has no curl
// extension, so those two schemes are implemented here over a raw socket -
// exactly the code path a real application would have.

declare(strict_types=1);

$url = isset($_GET['url']) ? (string) $_GET['url'] : '';
header('Content-Type: text/plain; charset=utf-8');

if ($url === '') {
    echo "SSRF endpoint. usage: /fetch.php?url=<url>\n";
    exit;
}

$scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));

function read_socket($fp, float $seconds = 3.0): string
{
    stream_set_timeout($fp, (int) $seconds);
    $out = '';
    while (!feof($fp)) {
        $chunk = fread($fp, 4096);
        if ($chunk === false || $chunk === '') {
            break;
        }
        $out .= $chunk;
    }
    return $out;
}

function fetch_gopher(string $url): string
{
    $parts = parse_url($url);
    $host = $parts['host'] ?? '127.0.0.1';
    $port = (int) ($parts['port'] ?? 70);

    $fp = @fsockopen($host, $port, $errno, $errstr, 3.0);
    if (!$fp) {
        return "gopher connect to {$host}:{$port} failed: {$errstr}";
    }

    // Everything after the first `_` is the request, percent-decoded once, as
    // the gopher URL scheme defines it.
    $payload = '';
    $at = strpos($url, '_');
    if ($at !== false) {
        $payload = urldecode(substr($url, $at + 1));
    }
    if ($payload !== '') {
        fwrite($fp, $payload);
        fflush($fp);
    }
    $out = read_socket($fp);
    fclose($fp);
    return $out === '' ? "gopher: connected to {$host}:{$port}, no reply\n" : $out;
}

function fetch_dict(string $url): string
{
    $parts = parse_url($url);
    $host = $parts['host'] ?? '127.0.0.1';
    $port = (int) ($parts['port'] ?? 2628);
    $command = ltrim($parts['path'] ?? '', '/');
    $command = urldecode($command === '' ? 'PING' : $command);

    $fp = @fsockopen($host, $port, $errno, $errstr, 3.0);
    if (!$fp) {
        return "dict connect to {$host}:{$port} failed: {$errstr}";
    }
    fwrite($fp, $command . "\r\n");
    fflush($fp);
    $out = read_socket($fp);
    fclose($fp);
    return $out === '' ? "dict: connected to {$host}:{$port}, no reply\n" : $out;
}

switch ($scheme) {
    case 'gopher':
        echo fetch_gopher($url);
        break;
    case 'dict':
        echo fetch_dict($url);
        break;
    case 'http':
    case 'https':
    case 'file':
    case 'php':
    case 'data':
    case 'ftp':
        $context = stream_context_create([
            'http' => ['timeout' => 3, 'follow_location' => 0, 'ignore_errors' => true],
            'ssl' => ['verify_peer' => false, 'verify_peer_name' => false],
        ]);
        $data = @file_get_contents($url, false, $context);
        echo $data === false ? "fetch failed for {$url}\n" : $data;
        break;
    default:
        echo "unsupported scheme: {$scheme}\n";
}
