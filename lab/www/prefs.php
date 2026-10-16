<?php
// A preferences endpoint, of the kind that stores a user's settings in a cookie
// as a serialized blob and reads them back on every request. The pattern is
// everywhere and the call is the whole problem: `unserialize()` instantiates
// whatever the string says, and the string came from the client.
//
// `allowed_classes` is not set. That is the vulnerable shape, and it is the
// default shape - the option has to be opted into, so the code that is wrong is
// the code that looks most ordinary.

declare(strict_types=1);

require_once __DIR__ . '/Cache.php';

// A preferences endpoint has a session; that is what preferences hang off. It is
// also what makes the session file a live target: `session_start()` reads the
// file and deserializes whatever is in it, so anything that can put bytes there
// has put a serialized object in front of the function.
session_start();

header('Content-Type: text/plain; charset=utf-8');

if (!isset($_COOKIE['prefs'])) {
    echo "preferences endpoint. no prefs cookie set.\n";
    exit;
}

$prefs = unserialize($_COOKIE['prefs']);

echo "preferences loaded\n";
if (is_object($prefs)) {
    echo "a " . get_class($prefs) . "\n";
} elseif (is_array($prefs)) {
    echo "an array of " . count($prefs) . "\n";
} else {
    echo gettype($prefs) . "\n";
}
