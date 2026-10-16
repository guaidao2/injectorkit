"""A cmd.exe endpoint, for the dialect a Linux lab cannot run.

The lab in `setup.sh` covers sh, bash and PowerShell. The Windows command
interpreter is a fourth language, and there is nowhere on a Linux box to run it:
`wine` is not installed and cmd.exe does not run natively. But the machine
driving the lab is often Windows, and cmd.exe is right there - so this serves the
same three shapes as `lab/www/cmdi.php` on the host, and the acceptance runner
uses it when it is reachable.

What it is and is not:

  * It runs commands **as you, on your machine**. That is what a command injection
    target is, and it is also the one thing here that can do real damage, so it
    does not start without `--i-know-what-this-is`: the same rule the tool applies
    to exploitation, for the same reason. Nothing in the acceptance runner starts
    it; you start it, and you stop it when you are done.
  * It binds to 127.0.0.1 only. Nothing outside this machine can reach it, and it
    refuses to bind anywhere else.
  * `/safe` escapes its value, exactly as the PHP endpoint does, so the negative
    control means the same thing on both.

    python lab/cmdwin.py --i-know-what-this-is
"""

from __future__ import annotations

import subprocess
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = 8087
CONSENT = "--i-know-what-this-is"
# A command that does not come back is not an answer, and the arithmetic probes
# are all short. Anything slower than this is a payload that reached the command
# as an argument and made it wait - which is information, not a reason to hang.
TIMEOUT = 20


def run(command: str) -> str:
    done = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        errors="replace",
    )
    return (done.stdout or "") + (done.stderr or "")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_GET(self) -> None:  # noqa: N802 - the base class names it
        parts = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parts.query)

        if "cmd" in query:
            # The value is the command.
            value = query["cmd"][0]
            body = f"cmd: {value}\r\n" + run(value)
        elif "host" in query:
            # The value is an argument to a command the page chose. `ping -n 1`
            # is the Windows spelling, and it waits on a name it cannot resolve,
            # which is the same shape the PHP endpoint's `ping` has.
            value = query["host"][0]
            body = f"running: ping -n 1 -w 1000 {value}\r\n" + run(
                f"ping -n 1 -w 1000 {value}"
            )
        elif "safe" in query:
            # The control: the same value, escaped. cmd treats a metacharacter
            # inside quotes as literal, so quoting it is what escaping means
            # here - the same intent as `escapeshellarg` on the PHP side.
            value = query["safe"][0]
            body = f"running: ping (escaped) {value}\r\n" + run(
                "ping -n 1 -w 1000 " + subprocess.list2cmdline([value])
            )
        else:
            body = (
                "cmd endpoints.\r\n"
                "  ?cmd=...    the value is the command\r\n"
                "  ?host=...   the value is an argument to a command the page runs\r\n"
                "  ?safe=...   the value is escaped first\r\n"
            )

        payload = body.encode("utf-8", "replace")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        if "--verbose" in sys.argv:
            print(f"  {self.address_string()} {format % args}", flush=True)


def main() -> int:
    if sys.platform != "win32":
        print("this endpoint is for a Windows host; the Linux lab has its own")
        return 1
    if CONSENT not in sys.argv:
        print("This serves an endpoint that runs commands as you, on this machine.")
        print("It does not start without being asked, and it binds to 127.0.0.1 only.")
        print()
        print("Start it when you mean to point a run at it, and stop it afterwards:")
        print()
        print(f"    python lab/cmdwin.py {CONSENT}")
        return 2
    server = HTTPServer(("127.0.0.1", PORT), Handler)
    print(f"cmd endpoint on http://127.0.0.1:{PORT}/ - running commands as you")
    print("Ctrl+C to stop. Do not leave it running.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
