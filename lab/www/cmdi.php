<?php
// Command execution endpoints, in the shapes a web application actually has.
//
// The interesting difference is not which shell it is - it is where the value
// lands. A parameter that *is* the command is a different injection from one
// that is appended to a command the application already decided to run, and the
// payloads are different too: the second has to break out of the first command
// before it can do anything.
//
// The third parameter is the control. It takes the same value and escapes it, so
// a tool that reports a finding here is reporting something that is not there.

declare(strict_types=1);

header('Content-Type: text/plain; charset=utf-8');

$cmd = isset($_GET['cmd']) ? (string) $_GET['cmd'] : null;
$host = isset($_GET['host']) ? (string) $_GET['host'] : null;
$bash = isset($_GET['bash']) ? (string) $_GET['bash'] : null;
$ps = isset($_GET['ps']) ? (string) $_GET['ps'] : null;
$safe = isset($_GET['safe']) ? (string) $_GET['safe'] : null;

if ($cmd === null && $host === null && $bash === null && $ps === null && $safe === null) {
    echo "command endpoints.\n";
    echo "  ?cmd=...    the value is the command, run by /bin/sh\n";
    echo "  ?host=...   the value is an argument to a command the page runs\n";
    echo "  ?bash=...   the value is the command, run by bash explicitly\n";
    echo "  ?ps=...     the value is the command, run by PowerShell\n";
    echo "  ?safe=...   the value is escaped first\n";
    exit;
}

if ($ps !== null) {
    // PowerShell, which is also the shell on a modern Windows host. A different
    // language rather than a differently-named one: its own way of printing and
    // its own way of computing, so a payload written for a POSIX shell answers
    // `\5` here where the proof wants `5`.
    echo "pwsh: {$ps}\n";
    system('pwsh -NoProfile -Command ' . escapeshellarg($ps));
    exit;
}

if ($bash !== null) {
    // Named on purpose. An application that shells out to bash rather than to
    // /bin/sh is a different target: the dialect supports things the POSIX one
    // does not, and a tool that only knows the POSIX set misses them here.
    echo "bash: {$bash}\n";
    system('bash -c ' . escapeshellarg($bash));
    exit;
}

if ($cmd !== null) {
    // The value is the whole command. This is the shape that turns up in an
    // admin panel or a diagnostic page somebody left switched on.
    echo "cmd: {$cmd}\n";
    system($cmd);
    exit;
}

if ($host !== null) {
    // The value is one argument of a command the page chose. Anything injected
    // here has to end this argument and start its own command.
    $command = 'ping -c 1 -W 1 ' . $host;
    echo "running: {$command}\n";
    system($command . ' 2>&1');
    exit;
}

// The control: the same value, escaped. A tool that reports a finding against
// this one is reading its own payload back rather than observing an effect.
$command = 'ping -c 1 -W 1 ' . escapeshellarg((string) $safe);
echo "running: {$command}\n";
system($command . ' 2>&1');
