# InjectorKit

[简体中文](README.zh-CN.md) · English · [Guide](GUIDE.md)

An exploitation toolkit for CTF and authorized penetration testing.

InjectorKit is the offensive counterpart to a traffic-driven scanner. It does
not ask "is this parameter vulnerable" and stop there; it probes, reads the
evidence, decides what to try next, adapts when a filter refuses, and keeps
going until it has an exploit or has proven the path closed.

The classes it covers are SSRF, PHP and Java protocol wrappers (`php://`,
`gopher://`, `dict://`, `data://`, `phar://`, `jar:`, `jrt:`) and command
injection. Further classes, including deserialization, are built on the same
engine.

## Start here

A URL with a parameter is the whole input. The tool finds the parameters, asks
what the target will accept, and reports what it proved:

    python injectorkit.py ssrf -u "http://target/api/fetch?url=http://example.com"
    python injectorkit.py proto -u "http://target/?file=index.php"
    python injectorkit.py cmdi -u "http://target/ping?host=127.0.0.1"

A body is a form post unless you say otherwise, so a parameter behind a form
takes `--data` rather than a query string:

    python injectorkit.py proto -u "http://target/" --data "file=index.php" --param file

When the page has a form rather than a query string, let it read the form:

    python injectorkit.py proto -u "http://target/" --forms

When you already know which file matters, say so - the tool asks for that one
instead of guessing:

    python injectorkit.py proto -u "http://target/?file=x" --read /flag

When you want the exploit rather than the finding, it is gated behind one flag:

    python injectorkit.py proto -u "http://target/?file=x" --exploit --os-cmd 'id'
    python injectorkit.py proto -u "http://target/?file=x" --exploit --os-shell

Every run prints what it is doing as it goes, and ends with what it proved, what
it ruled out, and what it never got to. `-q` keeps only the result, `-v` adds the
requests. `python injectorkit.py <class> -h` lists that class's options.

## Requirements

Python 3.11 or newer. The only third-party package is `cryptography`, and only
the interactsh backend needs it:

    pip install -r requirements.txt

Everything else is the standard library, and the tool runs from a checkout. The
import is guarded, so without `cryptography` the out-of-band options tell you
what to install and every other feature works as usual - including the local
callback listener, which needs nothing.

    pip install -e .          # optional: get an `injectorkit` command on PATH

## Tests

    python -m unittest discover -s tests -t .

Offline: no target, no network, no PHP, and nothing to install. They cover the
layers the modules are built on - message parsing, parameter placement, mutation
generations, evidence judging, the board, the priors, protocol bytes, the filter
chain's size, and the output rules - so a change to the engine can be checked
without a lab.

`lab/` holds the targets used while developing, and `lab/acceptance.py` is how a
release is measured: thirteen scenarios, each asked twice - once by hand, once by
the tool - and compared. Both are for working on InjectorKit; nothing in the
tool needs them.

## Behind a login

Point the tool at the identity you are already logged in as. There is nothing to
configure and nothing for it to log in to:

    python injectorkit.py ssrf -u "http://target/admin/export?file=x" \
        -C "PHPSESSID=abc123; csrf=xyz" \
        -H "Authorization: Bearer eyJhbGciOi..."

- `-C/--cookie` takes the cookie string as a browser shows it, and a pasted
  `Cookie: ...` line is accepted exactly as it comes.
- `-H/--header` carries anything else - a bearer token, an API key, a house
  authentication header. `-H` also makes a header injectable, which is how a
  custom authentication header becomes a position worth testing at all.
- `--basic-auth USER:PASSWORD` encodes it for you.

Two rules make this safe against a live session. A cookie is **merged** with
whatever the request already carries rather than replacing it - a CSRF token in
the request would otherwise be dropped, ending the very session this exists to
keep. And a header the request already names wins over the command-line value,
because a request that names its own identity is more specific than a default.

## Usage

    python injectorkit.py -h
    python injectorkit.py ssrf -h
    python injectorkit.py ssrf -u "http://target/api/fetch?url=http://example.com"
    python injectorkit.py ssrf -u "http://target/api/fetch?url=x" --param url --oob 10.0.0.5:8081
    python injectorkit.py proto -u "http://target/?file=index.php"
    python injectorkit.py proto -r burp.txt --param file --oob 10.0.0.5:8081
    python injectorkit.py cmdi -u "http://target/ping?host=127.0.0.1"

Three classes so far. `ssrf` asks what a URL parameter can reach; `proto` asks
what a path parameter will accept and hand back - `php://filter` source
disclosure, `data://` execution, `phar://`, `zip://`, `jar:`, `jrt:`,
`netdoc://`, and the JNDI schemes; `cmdi` asks which shell a parameter reaches
and what it will run there.

### Command injection

The question is arithmetic: the tool asks the target to print two fresh markers
with a computed number between them. A page that reflects the input returns the
expression; only a shell that ran it returns the number. The payload never
contains the answer, so a page echoing it cannot pass.

Because that question does not depend on the shell, the shell is something to
search rather than assume. `sh`, `bash`, PowerShell and the Windows command
interpreter are modelled as languages that can print a literal and print a sum,
crossed with the ways a command can be started - the value is the whole command,
or it is an argument to a command the page already runs and has to be ended
first. Getting past a filter is not the answer here, so the search keeps climbing
until something actually runs.

When it does, `--os-cmd` runs one command through the shape that was proved to
work, and reports honestly if the injection stopped working between proving it
and using it:

    python injectorkit.py cmdi -u "http://target/ping?host=127.0.0.1" \
        --exploit --os-cmd 'id; uname -a'

### Getting a shell

Two routes to execution through an `include()` point, and which one applies is
decided by the target rather than by preference:

- `--exploit` builds a `php://filter` chain on the fly and runs it - `--os-shell`
  for a live session, `--os-cmd` for one command. This needs the application to
  accept `php://filter`.
- `--log-path /var/log/nginx/access.log` plants PHP source in a file the server
  writes for itself, then includes it. This needs nothing but a plain path, which
  is what a target refusing every wrapper still allows.

Both run commands on the target, so both require `--exploit`:

    python injectorkit.py proto -u "https://target/" --forms --exploit \
        --log-path /var/log/nginx/access.log --os-cmd 'id'

### Reaching deserialization

`--make-phar` writes the archive offline, because building one must not require
PHP to be installed:

    python injectorkit.py proto -u "https://target/" --make-phar evil.phar \
        --phar-class SomeFrameworkClass --phar-set 'path=/tmp/pwn'

Upload it yourself, then point `--upload` at where it landed. Worth knowing
before relying on this: on PHP 8, opening a phar does **not** unserialize its
metadata - only `(new Phar(...))->getMetadata()` does, so the chain needs the
target to ask for the metadata. Framework code does; a plain `include` does not.

### Running the same scan twice

Progress is kept automatically under `.injectorkit/`, keyed by host and page. An
action that already ran on a page is not run again, so a second scan of the same
page costs nothing rather than repeating every request to reach an answer already
on the board.

    --flush-session     forget what earlier runs learned about this host
    --state FILE        keep it somewhere of your own instead
    --retries N         try again after a dropped connection (default: 1)

Findings are printed in colour when a person is reading them, and as plain text
when the output is a pipe or a file - so nothing parsing it has to strip escape
sequences. `--color always` and `--color never` override that.

A run in a terminal opens with the project banner. Piped output and `-q` skip it,
so a script never has to filter it out.

Each vulnerability class is a subcommand with its own options plus the shared
engine options (transport, bypass budget, progress store, verbosity).

### Callbacks

A blind SSRF, a blind command injection or a blind XXE leaves no trace in the
response; the only evidence is a connection the target makes to an address we
chose. There are two ways to receive it, and the choice is about where the
target can reach:

    --oob 10.0.0.5:8081        a listener here; the target has to be able to
                               reach this machine
    --oob-interactsh oast.pro  a public or self-hosted interactsh deployment;
                               the callback name resolves from anywhere, which
                               is what works from behind NAT and against hosts
                               on the internet

A private deployment takes `--oob-token`. Without either option, the
out-of-band actions skip themselves rather than plant a payload that can never
report back.

### Getting past a filter

    --via "http://allowed/redirect?to={target}"

A blocklist can be argued with: address spellings, encodings and DNS aliases all
give it something new to miss. A whitelist cannot - the destination has to be
named as something the filter accepts and reach somewhere else, which is what
`--via` is for. The template is the operator's because only they know what the
target trusts.

Out of the box the engine already reaches past the usual filters:

- address spellings an inet_aton-style resolver accepts: decimal, octal
  (padded or not), hexadecimal, the short form, IPv4-mapped IPv6, a trailing dot
- DNS aliases that resolve back to the address (`127.0.0.1.nip.io`), which a
  filter that parses the destination cannot see through either
- `--rebind INTERNAL,EXTERNAL`, which tries each destination again under a name
  that alternates between two addresses - what gets past a check that resolves
  the name once and connects later
- requests written over gopher, which is how a metadata service that demands
  `Metadata-Flavor: Google` or `Metadata: true` is reached at all - a URL
  parameter cannot add a header
- destinations assembled from two parameters (`?host=&path=`), which no
  single-parameter payload can fill in

### Where the parameters actually are

A single URL only reaches the parameters in the URL. Everything else is in a
body somewhere:

    --forms              fetch the page and submit every form it declares, with
                         the fields the page declares
    --targets targets.txt  one target per line - a URL, or the path of a saved raw
                         request

`--forms` is what makes a login page, a search box or an upload widget testable
from one address: the request is built the way the page builds it - GET fields in
the query, POST fields in the body, upload forms as real multipart - and each one
becomes its own target.

A parameter is addressed wherever it lives: `query:url`, `body:url`,
`cookie:url`, `multipart:url`, `json:user.avatar`, or `json -> ref` for a JSON
field inside a parameter's value.

### Acting on what was found

    --exploit --webroot /var/www/html              # write a shell through Redis
    --exploit --fpm-script /var/www/html/index.php # run code through PHP-FPM

Off by default, because writing a file or running a command on a target is the
operator's decision. When on, the follow-up is derived from the fingerprint: the
address and port come from the service that answered, the paths from the
operator, and the result is verified - a shell that was written but does not run
is reported as exactly that.

## How it works

A fixed payload list answers one question once, and real targets answer
partially: a scheme is blocked but an alias is not, a port is filtered but a
redirect is not, a service answers but only after the right handshake. The path
to an exploit is a sequence of questions where each answer changes the next one.

So the unit of work is a transition over shared facts:

    state + evidence -> next state, next action

Every module contributes a state graph. A shared blackboard holds what has been
learned about the target: reachable ports, the response channel (direct echo,
error echo, timing only, out-of-band), the filter profile, accepted schemes,
fingerprinted internal services, and dead ends that must not be retried.

Payloads are never stored, they are derived: a semantically correct seed plus
meaning-preserving mutators, ordered by generation, with the generation that
gets past a filter remembered so later actions start there.

Which rewrite to try first is learned rather than hard-coded. Every rewrite that
gets past a filter deposits weight, every one that is refused takes weight away,
and weight evaporates with time so a verdict reached on one target does not rule
forever. The table lives in `.injectorkit/pheromone.json` and is shared between
engagements, which is what makes the second target of a series cheaper than the
first. It orders attempts; it never decides that an attempt is impossible.
`--no-pheromone` turns it off and `--pheromone-file` moves it.

Evidence decides: a signature only the target produces, content that appears
once the requested encoding is undone, a delay inside the range the payload
asked for, or a callback arriving at the listener we planted. A response
changing is not a finding, and clearing a filter is not a hit - a rewrite that
only stopped being refused never earns the weight a confirmed one does.

## License

MIT. See [LICENSE](LICENSE).

Authors: coolmoon & guaidao2.
