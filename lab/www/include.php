<?php
// Local file inclusion endpoint. The wrapper family (php://filter, data://,
// phar://) is what turns "read a file" into "read it in an encoding of my
// choosing" and, with phar, into deserialization.

declare(strict_types=1);

// A real application has its framework loaded before it includes anything, and
// that is what gives a phar metadata blob a class to build. Without this the
// archive still opens, the metadata still unserializes, and it comes back as
// __PHP_Incomplete_Class - which does nothing at all.
require_once __DIR__ . '/Cache.php';

$file = isset($_GET['file']) ? (string) $_GET['file'] : '';
header('Content-Type: text/plain; charset=utf-8');

if ($file === '') {
    echo "LFI endpoint. usage: /include.php?file=<path-or-wrapper>\n";
    exit;
}

echo "<!-- include({$file}) -->\n";
include($file);
