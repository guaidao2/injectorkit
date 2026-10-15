<?php
// Open redirect. Useful for reaching a destination through a hop the caller was
// not allowed to name directly.

declare(strict_types=1);

$to = isset($_GET['to']) ? (string) $_GET['to'] : '';
if ($to === '') {
    http_response_code(400);
    echo "usage: /redirect.php?to=<url>\n";
    exit;
}
header('Location: ' . $to, true, 302);
echo "redirecting to {$to}\n";
