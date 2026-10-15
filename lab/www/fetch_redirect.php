<?php
// SSRF endpoint that follows redirects, the way most HTTP clients do.
//
// This is the one that matters against a whitelisting filter: the value the
// application is handed may name an allowed host, and still end up somewhere
// else once that host answers with a Location.

declare(strict_types=1);

$url = isset($_GET['url']) ? (string) $_GET['url'] : '';
header('Content-Type: text/plain; charset=utf-8');

if ($url === '') {
    echo "SSRF endpoint (follows redirects). usage: /fetch_redirect.php?url=<url>\n";
    exit;
}

$context = stream_context_create([
    'http' => [
        'timeout' => 6,
        'follow_location' => 1,
        'max_redirects' => 3,
        'ignore_errors' => true,
    ],
    'ssl' => ['verify_peer' => false, 'verify_peer_name' => false],
]);

$data = @file_get_contents($url, false, $context);
echo $data === false ? "fetch failed for {$url}\n" : $data;
