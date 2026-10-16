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

// The framework starts a session too, and that is what makes this endpoint the
// place a session file becomes reachable: `session_start()` reads the file and
// hands its contents to `unserialize()`, and the same request that includes a
// file can be pointed at the file it just read.
session_start();

// A framework keeps something in the session - a flash message, a CSRF token, a
// visit counter. This one counts requests, which is the smallest thing that
// leaves the session file non-empty and so visibly a session file rather than an
// empty file that might equally be a missing one.
$_SESSION['seen'] = ($_SESSION['seen'] ?? 0) + 1;

$file = isset($_GET['file']) ? (string) $_GET['file'] : '';
header('Content-Type: text/plain; charset=utf-8');

if ($file === '') {
    echo "LFI endpoint. usage: /include.php?file=<path-or-wrapper>\n";
    exit;
}

echo "<!-- include({$file}) -->\n";
include($file);
