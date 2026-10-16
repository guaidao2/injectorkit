<?php
// A plain upload endpoint. It keeps the name the client sent and writes into a
// directory under the web root, which is the shape the phar chain needs: the
// uploaded file has to be reachable afterwards through a path the caller can
// name. The reply names that path, because guessing it is not a plan.

declare(strict_types=1);

$dir = __DIR__ . '/uploads';
if (!is_dir($dir)) {
    mkdir($dir, 0777, true);
}

header('Content-Type: text/plain; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !isset($_FILES['file'])) {
    echo "upload endpoint. POST one file in the 'file' field.\n";
    exit;
}

$name = basename((string) $_FILES['file']['name']);
$target = $dir . '/' . $name;
$moved = move_uploaded_file($_FILES['file']['tmp_name'], $target);

echo $moved ? "stored: uploads/{$name}\n" : "failed\n";
