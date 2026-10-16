<?php
// A configuration loader of the kind a framework has and an application calls
// without thinking about it.
//
// `config` names a phar to load settings from. The archive is opened and its
// metadata asked for - which is what makes an uploaded phar dangerous on PHP 8,
// where merely opening an archive no longer deserializes anything. There is no
// extension check, because a loader that decides by name is a loader written for
// a test: it opens what it is given.
//
// `read` includes a snippet the deployment named, which is how a loader lets one
// more file be pulled in.
//
// The two are handled independently rather than with one taking precedence. A
// loader that stopped at the first parameter it recognised would answer a
// request about the other one with the same page every time, and a tool testing
// one parameter at a time cannot tell that apart from a parameter that does
// nothing.

declare(strict_types=1);

require_once __DIR__ . '/Cache.php';

header('Content-Type: text/plain; charset=utf-8');

$config = isset($_GET['config']) ? (string) $_GET['config'] : '';
$read = isset($_GET['read']) ? (string) $_GET['read'] : '';

if ($config === '' && $read === '') {
    echo "config loader.\n";
    echo "  ?config=path/to/config.phar   load settings from an archive\n";
    echo "  ?read=path/to/snippet.php     include a snippet\n";
    exit;
}

if ($config !== '') {
    if (!is_file($config)) {
        echo "no such config: {$config}\n";
    } else {
        try {
            $phar = new Phar($config);
            $metadata = $phar->getMetadata();
            echo "loaded {$config}\n";
            if (is_object($metadata)) {
                echo "metadata is a " . get_class($metadata) . "\n";
            } elseif ($metadata === null) {
                echo "metadata is empty\n";
            } else {
                echo "metadata is " . gettype($metadata) . "\n";
            }
        } catch (Throwable $error) {
            echo "could not load {$config}: " . $error->getMessage() . "\n";
        }
    }
}

if ($read !== '') {
    if (!is_file($read)) {
        echo "no such snippet: {$read}\n";
    } else {
        include $read;
        echo "included {$read}\n";
    }
}
