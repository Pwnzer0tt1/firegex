#!/usr/bin/env python3
"""The unified service model, against a live instance.

Two layers, exercised separately and together: a network layer that says how traffic is
intercepted, and a chain of filters that says what happens to it. The point of the tests
is that the two really are independent — the same filters block on either transport, and
the chain can be reordered and edited without the service being recreated.
"""

import argparse
import base64
import secrets
import socket
import time

from utils.colors import colors, puts, sep
from utils.firegexapi import FiregexAPI
from utils.tcpserver import TcpServer
from utils.tls_helpers import (capture_device_present, capture_on,
                               generate_self_signed_cert_key, tls_alpn_choice,
                               tls_connect_send_recv)

# Written against the documented API: parameters annotated with a model, verdicts from
# the library. It is the same code the NFQUEUE binary would run, which is the property
# worth testing — there is one Python API, not one per transport.
PYFILTER_CODE = """from firegex.pyfilters import pyfilter, ACCEPT, REJECT
from firegex.pyfilters.models import RawPacket


@pyfilter
def refuse_marker(packet: RawPacket):
    return REJECT if b"PYBLOCK" in packet.data else ACCEPT
"""

# One file, two filters: one that wants parsed HTTP and one that wants raw payloads.
# Nothing declares a protocol — asking for an HttpRequest is what makes this an HTTP
# filter file, and the two annotations coexist because `http` provides both. This used
# to be impossible to save: the backend sent the *service's* protocol to the datapath,
# so an HTTP filter on a TCP service was refused for asking for an HttpRequest, which is
# the only thing an HTTP filter does.
HTTP_PYFILTER_CODE = """from firegex.pyfilters import pyfilter, ACCEPT, REJECT, ExceptionAction
from firegex.pyfilters.models import HttpRequest, RawPacket

# The stand-in service echoes whatever it is sent, so the reply to an HTTP request is
# not itself a valid HTTP response. The default is to refuse a stream the parser cannot
# read; here that is the test's own doing rather than the filter's, so it is turned off.
# (Setting this used to be silently ignored, which is how the gate that read it was
# found to be checking the wrong enum.)
FGEX_INVALID_ENCODING_ACTION = ExceptionAction.ACCEPT


@pyfilter
def refuse_traversal(request: HttpRequest):
    return REJECT if "../" in (request.url or "") else ACCEPT


@pyfilter
def look_at_the_bytes(packet: RawPacket):
    return ACCEPT
"""

# A datagram filter: only RawPacket, which is the one model that does not need a stream
# underneath it. Everything else — an assembled TCP stream, a parsed HTTP message —
# declines to be built on a datagram, so a filter asking for one would never be called.
UDP_PYFILTER_CODE = """from firegex.pyfilters import pyfilter, ACCEPT, REJECT
from firegex.pyfilters.models import RawPacket


@pyfilter
def refuse_marker(packet: RawPacket):
    return REJECT if b"PYDENY" in packet.data else ACCEPT
"""



exit_code = 0


class UdpEcho:
    """A UDP echo service, and a client that talks to it through firegex.

    Deliberately not the TCP helper with the protocol swapped: a datagram exchange has
    no connection to establish, so "was it refused" is "did an answer come back before
    the timeout" rather than "did the socket close".
    """

    def __init__(self, port: int, ipv6: bool = False):
        self.port = port
        self.ipv6 = ipv6
        self.sock = None
        self.thread = None

    def start(self):
        # A thread rather than a process: an echo loop on a socket needs no isolation,
        # and closing the socket is a cleaner way to stop it than killing a child.
        import socket as s
        import threading

        self.sock = s.socket(s.AF_INET6 if self.ipv6 else s.AF_INET, s.SOCK_DGRAM)
        self.sock.setsockopt(s.SOL_SOCKET, s.SO_REUSEADDR, 1)
        self.sock.bind(("::1" if self.ipv6 else "127.0.0.1", self.port))

        def serve():
            while True:
                try:
                    data, peer = self.sock.recvfrom(65535)
                except OSError:
                    return  # the socket was closed; that is how this loop ends
                try:
                    self.sock.sendto(data, peer)
                except OSError:
                    return

        self.thread = threading.Thread(target=serve, daemon=True)
        self.thread.start()
        time.sleep(0.3)

    def stop(self):
        if self.sock:
            self.sock.close()
            self.sock = None
        if self.thread:
            self.thread.join(timeout=2)
            self.thread = None

    def exchange(self, payload: bytes, timeout: float = 1.5):
        """Send one datagram and return the answer, or `None` if none came back."""
        import socket as s
        sock = s.socket(s.AF_INET6 if self.ipv6 else s.AF_INET, s.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(payload, ("::1" if self.ipv6 else "127.0.0.1", self.port))
            return sock.recvfrom(65535)[0]
        except (TimeoutError, OSError):
            return None
        finally:
            sock.close()


MARKER = b"answered-by-your-own-proxy"


def gets_through(server, payload: bytes, attempts: int = 5) -> bool:
    """Does this traffic reach the service and come back?

    Retried, for the same reason `reaches_proxy` below is: one TCP exchange is a noisy
    way to observe a filter's decision, and a connection that fails for its own reasons
    is indistinguishable from one a filter refused. Retrying cannot turn a real block
    into a pass — a filter that refuses this payload refuses it on every attempt — so
    this removes noise without weakening the check.
    """
    for _ in range(attempts):
        if server.sendCheckData(payload):
            return True
        time.sleep(0.3)
    return False


def reaches_proxy(external, attempts: int = 6) -> bool:
    """Did traffic aimed at the service land on the operator's proxy instead?

    The proxy answers with a marker while the real service echoes, so the reply says
    which of the two the connection actually reached.

    Retried for a couple of seconds: the suite runs the transports back to back on the
    same ports, and a listener from the previous case can still be going away. Waiting
    for the answer to settle does not weaken the check — a hand-off that never works
    still never answers with the marker.
    """
    for attempt in range(attempts):
        try:
            external.connect_client()
            try:
                external.send_packet(b"hello", server_reply=MARKER)
                if external.recv_packet() == MARKER:
                    return True
            finally:
                external.close_client()
        except OSError:
            pass
        time.sleep(0.4)
    return False


def check(label: str, ok: bool, detail: str = ""):
    global exit_code
    if ok:
        puts(f"  [+] {label}", color=colors.green)
    else:
        exit_code = 1
        puts(f"  [-] {label} {detail}", color=colors.red)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--address", "-a", type=str, required=False,
                        default="http://127.0.0.1:4444/", help="Address of firegex backend")
    parser.add_argument("--password", "-p", type=str, required=True, help="Firegex password")
    parser.add_argument("--port", "-P", type=int, required=False, default=1337,
                        help="Port of the test service")
    parser.add_argument("--ipv6", "-6", action="store_true", default=False, help="Test IPv6")
    parser.add_argument("--transport", "-t", type=str,
                        choices=["proxy", "nfqueue", "external"],
                        default="proxy", help="Which network layer to test")
    parser.add_argument("--tls", action="store_true", default=False,
                        help="Put the service behind TLS")
    args = parser.parse_args()

    api = FiregexAPI(args.address)
    sep()
    puts(f"Services test: {args.transport} transport"
         f"{' + TLS' if args.tls else ''}{' (IPv6)' if args.ipv6 else ''}", is_bold=True)
    sep()

    if not api.login(args.password):
        puts("Login failed", color=colors.red)
        exit(1)

    ip = "::1" if args.ipv6 else "127.0.0.1"
    name = f"test-{secrets.token_hex(4)}"
    cert = key = None
    if args.tls:
        cert, key = generate_self_signed_cert_key(ip)

    handing_off = args.transport == "external"

    server = TcpServer(args.port, args.ipv6, tls_cert=cert if args.tls else None,
                       tls_key=key if args.tls else None)
    server.start()

    # The stand-in for a proxy the operator wrote themselves: it listens on a port of
    # its own while its client dials the service's, so the rules are what has to put it
    # in the path. It answers with a marker rather than echoing, because the real
    # service echoes too and two echoes cannot be told apart.
    external = TcpServer(args.port + 1, args.ipv6, proxy_port=args.port) if handing_off else None
    if external:
        external.start()

    service_id = None
    try:
        # --- the network layer ------------------------------------------------
        service_id = api.services_add(
            name, ip, args.port, args.transport, tls=args.tls, tls_cert=cert, tls_key=key,
            proxy_ip=ip if external else None,
            proxy_port=(args.port + 1) if external else None,
        )
        check("create a service", service_id is not None)
        if service_id is None:
            exit(1)

        listed = [s for s in api.services_list() if s["service_id"] == service_id]
        check("it shows up with its transport",
              len(listed) == 1 and listed[0]["transport"] == args.transport, str(listed))

        if handing_off:
            # Nothing of firegex is in the path here, so the whole point is that traffic
            # aimed at the service arrives at the operator's own proxy instead.
            check("start the hand-off", api.services_start(service_id))
            time.sleep(1)
            check("traffic aimed at the service reaches your proxy",
                  reaches_proxy(external), "it reached the real service instead")

            # A filter here would be one that never runs, so it is refused at the moment
            # it is attached rather than accepted and broken later.
            why = api.services_add_filter_error(service_id, "regex", "patterns")
            check("attaching a filter to a running hand-off is refused, naming the reason",
                  why is not None and "would never run" in why, str(why))

            # Stopped, it is only configuration, so it is stored — and then starting is
            # what refuses, with the same reason.
            api.services_stop(service_id)
            check("it can be attached while stopped",
                  api.services_add_filter(service_id, "regex", "patterns"))
            fid = api.services_filters(service_id)[0]["filter_id"]
            why = api.services_start_error(service_id)
            check("starting with a filter is refused, naming the reason",
                  why is not None and "would never run" in why, str(why))
            check("removing it lets the hand-off start again",
                  api.services_delete_filter(service_id, fid))
            check("and it starts", api.services_start(service_id))
            time.sleep(0.8)
            check("the hand-off still works", reaches_proxy(external))

            entries = api.services_logs(service_id)
            check("the log records the hand-off", any(
                "started on the external layer" in e["text"] for e in entries),
                str(entries[-3:]))
            raise SystemExit  # the rest of this suite is about filters, which this has none of

        # --- the filter chain -------------------------------------------------
        check("attach a regex filter", api.services_add_filter(service_id, "regex", "patterns"))
        chain = api.services_filters(service_id)
        check("the chain has one link", len(chain) == 1, str(chain))
        regex_filter = chain[0]["filter_id"]

        check("add a pattern",
              api.services_add_regex(service_id, regex_filter, "BLOCKME", mode="B"))

        # The engine that will run the pattern is the one that validates it, so a
        # pattern it cannot compile is refused here rather than at start time.
        why = api.services_add_regex_error(service_id, regex_filter, "(unclosed")
        check("a broken pattern is refused with the engine's own reason",
              why is not None and "parenthesis" in why.lower(), str(why))

        # --- the tester, which must agree with the engine ----------------------
        result = api.services_debug_regex(
            [{"id": "a", "expr": r"FLAG\{[a-z0-9]+\}", "case_sensitive": True},
             {"id": "b", "expr": "(broken", "case_sensitive": True}],
            b"give me FLAG{abc123} please")
        hits = {(m["id"], m["start"], m["end"]) for m in result.get("matches", [])}
        check("the tester finds the match where it is", ("a", 8, 20) in hits, str(hits))
        check("the tester names the pattern that will not compile",
              [e["id"] for e in result.get("errors", [])] == ["b"], str(result.get("errors")))

        # --- a mixed chain, on whichever layer -------------------------------
        # Both layers host an ordered chain of both kinds. They get there differently —
        # the proxy walks a list inside one process, NFQUEUE chains one process per
        # filter by base-chain priority — and the point of testing both identically is
        # that the difference does not reach the operator.
        check("attach a pyfilter", api.services_add_filter(service_id, "pyfilter", "python"))
        chain = api.services_filters(service_id)
        py_filter = [f["filter_id"] for f in chain if f["kind"] == "pyfilter"][0]
        check("store code written against the documented API",
              api.services_set_code(service_id, py_filter, PYFILTER_CODE))
        check("read the code back verbatim",
              api.services_get_code(service_id, py_filter) == PYFILTER_CODE)

        check("reorder the chain",
              api.services_reorder_filters(service_id, [py_filter, regex_filter]))
        chain = api.services_filters(service_id)
        check("the new order stuck",
              [f["filter_id"] for f in chain] == [py_filter, regex_filter], str(chain))
        check("reordering back",
              api.services_reorder_filters(service_id, [regex_filter, py_filter]))

        # --- traffic ----------------------------------------------------------
        check("start the service", api.services_start(service_id))
        time.sleep(1)

        if args.tls:
            # The service's own address, exactly as a client outside would dial it.
            # There is no second port to be pointed at any more: the engine decrypts at
            # the address the world connects to, so a TLS service occupies nothing that a
            # plain one does not.
            address = api.services_addresses(service_id)[0]
            ssl_port = args.port
            check("a TLS service reports no port of its own",
                  "ssl_port" not in address and "clear_port" not in address, str(address))
            got = tls_connect_send_recv(ssl_port, args.ipv6, b"harmless traffic")
            check("benign traffic gets through", got == b"harmless traffic", repr(got))
            got = tls_connect_send_recv(ssl_port, args.ipv6, b"carrying BLOCKME")
            check("matching traffic is blocked", not got or b"BLOCKME" not in got, repr(got))

            # --- the decrypted traffic has an interface of its own ------------------
            # The engine decrypts inside the process, so the plaintext is never a packet
            # on any interface — which is what removed the two loopback ports, and would
            # have removed any way to watch it. So the engine writes the stream out
            # itself, onto one device carrying every TLS service's plaintext and nothing
            # else. They are reconstructed packets: what crossed the wire was encrypted.
            if args.tls and capture_device_present():
                plaintext = capture_on("firegex0", 4.0, lambda: (
                    tls_connect_send_recv(ssl_port, args.ipv6, b"harmless traffic")))
                check("the capture interface carries the plaintext",
                      b"harmless traffic" in plaintext, repr(plaintext[-200:]))


        else:
            check("benign traffic gets through", gets_through(server, b"harmless traffic"))
            check("matching traffic is blocked", not server.sendCheckData(b"carrying BLOCKME"))

            # The reason the matcher keeps per-connection state: a pattern that lands
            # across two writes is still the pattern.
            server.connect_client()
            server.send_packet(b"split BLOC")
            time.sleep(0.3)
            server.send_packet(b"KME here")
            check("a pattern split across two writes is still caught",
                  server.recv_packet() != b"KME here")
            server.close_client()

            check("the pyfilter in the chain blocks too",
                  not server.sendCheckData(b"carrying PYBLOCK"))


        # The block is attributed to the rule that fired, not to the service.
        time.sleep(0.5)
        patterns = api.services_regexes(service_id, regex_filter)
        check("the block is counted against the pattern",
              any(p["blocked"] >= 1 for p in patterns), str(patterns))

        # --- editing a pattern in place ---------------------------------------
        # A typo in a rule is found while it is running, and retyping it as a new rule
        # loses its place in the chain. The row stays; what it matches changes.
        blockme = [p for p in patterns if base64.b64decode(p["regex"]) == b"BLOCKME"][0]
        check("the pattern had blocked something before the edit", blockme["blocked"] >= 1)

        check("a pattern is refused if it does not compile",
              api.services_edit_regex_error(
                  service_id, regex_filter, blockme["regex_id"],
                  regex=base64.b64encode(b"(unclosed").decode()) is not None)
        still = [p for p in api.services_regexes(service_id, regex_filter)
                 if p["regex_id"] == blockme["regex_id"]][0]
        check("and the refused edit left the rule exactly as it was",
              still["regex"] == blockme["regex"] and still["blocked"] == blockme["blocked"],
              str(still))

        before = api.services_stats(service_id)
        check("edit the pattern in place",
              api.services_edit_regex(service_id, regex_filter, blockme["regex_id"],
                                      regex=base64.b64encode(b"STOPME").decode()))
        edited = [p for p in api.services_regexes(service_id, regex_filter)
                  if p["regex_id"] == blockme["regex_id"]][0]
        check("the rule kept its identity", edited["regex_id"] == blockme["regex_id"])
        # The counts were about the text that used to be there. Carrying them over would
        # credit blocks to a matcher that never made them.
        check("and lost the counters that belonged to the old pattern",
              edited["blocked"] == 0, str(edited))

        # What must *not* happen is the chart losing them. Those connections were
        # refused, in those minutes, by this filter; a later typo fix has nothing to say
        # about that, and deleting the rows took a bite out of the timeline — on a filter
        # holding one pattern, it emptied it. They are handed to the filter instead.
        after = api.services_stats(service_id)
        check("the timeline keeps what the old pattern refused",
              sum(sum(sr["counts"]) for sr in after["series"])
              == sum(sum(sr["counts"]) for sr in before["series"]),
              f"{before['series']} -> {after['series']}")
        check("and so does the total, and the filter it belongs to",
              after["total"] == before["total"]
              and [f["blocked"] for f in after["filters"]] == [f["blocked"] for f in before["filters"]],
              f"{before['total']}/{[f['blocked'] for f in before['filters']]} -> "
              f"{after['total']}/{[f['blocked'] for f in after['filters']]}")
        # And the breakdown still adds up: those blocks belong to no pattern now, so
        # they are named rather than silently missing from a list that should sum to the
        # chart above it.
        check("the per-pattern breakdown names what no rule accounts for any more",
              any(row.get("residual") for row in after["patterns"]), str(after["patterns"]))
        check("so the shares still add up",
              sum(row["blocked"] for row in after["patterns"] + after["functions"])
              == after["total"],
              f"{after['patterns']} + {after['functions']} vs {after['total']}")

        # The edit reaches the datapath, not only the table.
        time.sleep(1)
        if args.tls:
            got = tls_connect_send_recv(ssl_port, args.ipv6, b"carrying STOPME")
            check("the new pattern is the one the datapath enforces",
                  not got or b"STOPME" not in got, repr(got))
        else:
            check("the new pattern is the one the datapath enforces",
                  not server.sendCheckData(b"carrying STOPME"))
            check("and the old one no longer blocks anything",
                  gets_through(server, b"carrying BLOCKME"))

        # Two identical rules in one filter are one rule twice: the second can never be
        # the reason for anything, and the list would say otherwise.
        check("add a second pattern",
              api.services_add_regex(service_id, regex_filter, "OTHERONE"))
        other = [p for p in api.services_regexes(service_id, regex_filter)
                 if base64.b64decode(p["regex"]) == b"OTHERONE"][0]
        check("editing one onto another is refused",
              api.services_edit_regex_error(
                  service_id, regex_filter, other["regex_id"],
                  regex=base64.b64encode(b"STOPME").decode()) is not None)
        check("remove the second pattern",
              api.services_delete_regex(service_id, regex_filter, other["regex_id"]))

        # Put it back, so everything after this reads the same as before.
        check("edit it back",
              api.services_edit_regex(service_id, regex_filter, blockme["regex_id"],
                                      regex=base64.b64encode(b"BLOCKME").decode()))
        # Blocked again, on both paths — and deliberately so, not only as a check: the
        # edit reset this rule's counters, and everything below reads the statistics per
        # pattern. Leaving it at zero would fail those tests for a reason that has
        # nothing to do with what they are about.
        time.sleep(1)
        if args.tls:
            got = tls_connect_send_recv(ssl_port, args.ipv6, b"carrying BLOCKME")
            check("and the original pattern blocks again",
                  not got or b"BLOCKME" not in got, repr(got))
        else:
            check("and the original pattern blocks again",
                  not server.sendCheckData(b"carrying BLOCKME"))
        time.sleep(0.5)

        # --- what the editor is allowed to suggest ----------------------------
        # Introspected from the library, so a model that gains a property gains a hint.
        # Checked against the library's own table rather than a list written here: a
        # second list is the thing this endpoint exists to avoid.
        described = api.services_pyfilter_api()
        names = {m["name"] for m in described["models"]}
        check("the library describes its own models",
              {"RawPacket", "HttpRequest", "TCPInputStream"} <= names, str(sorted(names)))
        raw = [m for m in described["models"] if m["name"] == "RawPacket"][0]
        members = {m["name"]: m for m in raw["members"]}
        check("with the metadata a filter may read",
              {"client_ip", "server_port", "is_tcp", "is_input"} <= set(members), str(sorted(members)))
        check("and only the payload marked writable",
              members["data"]["writable"] and not members["client_ip"]["writable"],
              str([(k, v["writable"]) for k, v in members.items() if v["writable"]]))
        check("HttpRequest belongs to http alone, RawPacket to everything",
              [m for m in described["models"] if m["name"] == "HttpRequest"][0]["protocols"] == ["http"]
              and len(raw["protocols"]) > 1, str(raw["protocols"]))
        check("the verdicts are described too",
              {v["name"] for v in described["verdicts"]}
              == {"ACCEPT", "REJECT", "DROP"}, str(described["verdicts"]))

        # --- what has been refused, and when ----------------------------------
        # The totals say which rule is doing the work; the timeline says when it
        # started, which a cumulative counter cannot.
        stats = api.services_stats(service_id)
        check("the stats name every filter in the chain",
              {f["id"] for f in stats["filters"]} == {f["filter_id"] for f in chain},
              str(stats["filters"]))
        check("the totals agree with the per-pattern counters",
              stats["total"] >= 1 and any(p["blocked"] >= 1 for p in stats["patterns"]),
              str(stats["total"]))
        # Every step is drawn whether or not anything landed in it — a chart with the
        # quiet minutes missing lies about the shape of a burst — and every series is as
        # long as the axis. The service is seconds old here, so the window it is given
        # is short by design; what has to hold is that the two agree.
        check("every bucket is present, including the quiet ones",
              len(stats["buckets"]) >= 1
              and all(len(sr["counts"]) == len(stats["buckets"]) for sr in stats["series"])
              and all(b - a == stats["bucket_seconds"]
                      for a, b in zip(stats["buckets"], stats["buckets"][1:])),
              str(stats["buckets"]))
        check("the timeline attributes the blocks to a filter",
              sum(sum(sr["counts"]) for sr in stats["series"]) >= 1, str(stats["series"]))

        # --- the range is one question, asked of everything ---------------------
        # Chart, totals and shares all count the window that was asked for. A page where
        # the chart honours a range and the table beside it reports all of time is a page
        # that contradicts itself.
        import time as _time
        now = int(_time.time())
        recent = api.services_stats(service_id, range_from=now - 900, range_to=now)
        check("a narrow range still sees what just happened",
              recent["total"] >= 1 and recent["range_to"] - recent["range_from"] <= 900,
              str((recent["total"], recent["range_from"], recent["range_to"])))
        check("its filters, patterns and functions count that same range",
              sum(f["blocked"] for f in recent["filters"]) == recent["total"],
              str([(f["name"], f["blocked"]) for f in recent["filters"]]))
        check("and the lifetime figure is reported beside it, not instead of it",
              recent["all_time"] >= recent["total"], str((recent["all_time"], recent["total"])))

        old = api.services_stats(service_id, range_from=now - 7200, range_to=now - 3600)
        check("a range that ended before any of it sees nothing",
              old["total"] == 0 and all(f["blocked"] == 0 for f in old["filters"]), str(old["total"]))

        # A wider window is the same rows in wider steps, never more bars than asked for.
        wide = api.services_stats(service_id, range_from=now - 24 * 3600, range_to=now, buckets=20)
        check("a wide range never multiplies the bars",
              wide["bucket_seconds"] >= recent["bucket_seconds"] and len(wide["buckets"]) <= 24,
              str((wide["bucket_seconds"], len(wide["buckets"]))))
        check("and asking beyond what is kept is clamped, saying how far back that is",
              api.services_stats(service_id, range_from=0, range_to=now)["range_from"]
              >= wide["kept_from"], str(wide["kept_from"]))

        # The step is the operator's to pick: five minutes is five minutes whether they
        # are looking at an hour or at a day, which is what makes two ranges comparable
        # by eye. Asked for in seconds, answered in whole stored buckets.
        stepped = api.services_stats(service_id, range_from=now - 6 * 3600,
                                     range_to=now, step=300)
        check("the step can be asked for instead of derived",
              stepped["bucket_seconds"] == 300, str(stepped["bucket_seconds"]))
        check("and it regroups the same rows rather than fetching different ones",
              sum(sum(sr["counts"]) for sr in stepped["series"]) == stepped["total"],
              str((stepped["total"], stepped["series"])))
        # Never refused, only widened: the request is reasonable, the chart it would draw
        # is not, and the answer says which step it actually used.
        melting = api.services_stats(service_id, range_from=now - 48 * 3600,
                                     range_to=now, step=1)
        check("a step finer than the history is widened to one whole bucket",
              melting["bucket_seconds"] >= 60 and len(melting["buckets"]) <= 400,
              str((melting["bucket_seconds"], len(melting["buckets"]))))

        # The hours before a service was running with a filter are not quiet hours, and
        # a chart of them reads as "nothing is happening" when it means "this did not
        # exist yet". Every range is floored there, exactly as it is floored at what is
        # still kept, and the range actually served says so.
        began = wide["filtering_since"]
        check("the service knows when it began filtering",
              began is not None and began <= now, str(began))
        check("and no range starts before that, however far back it asks",
              wide["range_from"] == began
              and api.services_stats(service_id, range_from=0, range_to=now)["range_from"] == began,
              str((wide["range_from"], began)))
        check("a window that ended before it began is answered as asked, and is empty",
              old["range_to"] <= began and old["total"] == 0
              and old["range_from"] < old["range_to"],
              str((old["range_from"], old["range_to"], began, old["total"])))

        # Which rule is doing the work, not just how much was refused. Raw counts hide a
        # chain where one pattern accounts for nearly everything.
        shares = [f["share"] for f in stats["filters"] if f["blocked"] > 0]
        check("every rule reports its share of the blocking",
              shares and abs(sum(f["share"] for f in stats["filters"]) - 100) < 1.5,
              str([(f["name"], f["blocked"], f["share"]) for f in stats["filters"]]))
        check("the patterns are broken down the same way",
              all("share" in p for p in stats["patterns"]), str(stats["patterns"][:2]))
        check("and the @pyfilter functions have a breakdown of their own",
              "functions" in stats, str(list(stats)))

        # How much of what arrived any of it amounts to. Packets come from the kernel's
        # own counters, so a filter cannot skew them; connections come from the proxy
        # engine, and only there is a refused share a division of like by like.
        # The engine reports its counters on a timer, so this is a number that arrives
        # rather than one that is there. Waiting for it is the test being correct about
        # the contract, not being lenient about it.
        traffic = stats["traffic"]
        if args.transport == "proxy":
            for _ in range(20):
                if traffic.get("connections"):
                    break
                time.sleep(0.5)
                traffic = api.services_stats(service_id)["traffic"]
        if args.transport != "proxy":
            check("the kernel's own counters say how much reached the service",
                  traffic["packets"] > 0 and traffic["bytes"] > 0, str(traffic))
        else:
            # Its rule lives in a nat chain, and conntrack walks that once per
            # connection: the counter there would be new connections wearing a packet
            # label. The engine reports connections properly instead.
            check("the proxy layer reports no packet count rather than a wrong one",
                  traffic["packets"] == 0, str(traffic))
        if args.transport == "proxy":
            check("the proxy layer counts connections, so the refused share is exact",
                  traffic["connections"] is not None
                  and traffic["refused_share"] is not None
                  and 0 < traffic["refused_share"] <= 100, str(traffic))
        else:
            # Not a hole in the reporting: this layer inspects packets and has no
            # connection to take a share of. Inventing one would mean dividing refused
            # connections by a packet count.
            check("the per-packet layer reports no connection share rather than a made-up one",
                  traffic["connections"] is None and traffic["refused_share"] is None,
                  str(traffic))

        # --- a second address, on the running service -------------------------
        # One service, one chain, more than one place it answers. The datapath is
        # already up, so this only points another address at it.
        addresses = api.services_addresses(service_id)
        check("the service reports where it is reachable",
              len(addresses) == 1 and addresses[0]["port"] == args.port, str(addresses))
        why = api.services_delete_address_error(service_id, addresses[0]["address_id"])
        check("its only address cannot be removed, saying why",
              why is not None and "only address" in why, str(why))

        # Behind TLS it has to speak TLS too: the engine re-encrypts towards whatever it
        # is protecting, on the new address exactly as on the first.
        second = TcpServer(args.port + 2, args.ipv6,
                           tls_cert=cert if args.tls else None,
                           tls_key=key if args.tls else None)
        second.start()
        try:
            why = api.services_add_address_error(service_id, ip, args.port + 2)
            check("protect a second address without restarting", why is None, str(why))
            check("both addresses are listed",
                  len(api.services_addresses(service_id)) == 2)
            time.sleep(1)
            if not args.tls:
                check("benign traffic to the new address gets through",
                      gets_through(second, b"harmless traffic"))
                # The same chain, on an address that did not exist when it started.
                check("the same chain filters the new address",
                      not second.sendCheckData(b"carrying BLOCKME"))
            else:
                # The same certificate and the same chain, on an address that did not
                # exist when the engine started. Nothing had to be arranged for it: there
                # is no per-address terminator any more, so adding one costs what adding
                # one costs without TLS.
                got = tls_connect_send_recv(args.port + 2, args.ipv6, b"harmless traffic")
                check("the new address is decrypted too",
                      got == b"harmless traffic", repr(got))
                got = tls_connect_send_recv(args.port + 2, args.ipv6, b"carrying BLOCKME")
                check("and the same chain filters it",
                      not got or b"BLOCKME" not in got, repr(got))

            # The service kept running throughout, which is the point of an address
            # having its own endpoints rather than being part of the service form.
            entries = api.services_logs(service_id)
            check("the log says the address was added without dropping anything",
                  any("also protecting" in e["text"] for e in entries), str(entries[-4:]))

            gone = [a for a in api.services_addresses(service_id)
                    if a["port"] == args.port + 2][0]["address_id"]
            check("remove it again", api.services_delete_address(service_id, gone))
            time.sleep(0.8)
            if not args.tls:
                check("the removed address is no longer filtered",
                      gets_through(second, b"carrying BLOCKME"))
            check("the original address is still protected",
                  args.tls or not server.sendCheckData(b"carrying BLOCKME"))
        finally:
            second.stop()

        # --- an address specified as a network interface ----------------------
        # An interface name instead of a fixed IP or CIDR range. The datapath intercepts
        # traffic directly on the interface.
        why_iface = api.services_add_address_error(service_id, "lo", args.port + 3)
        check("protect an address by interface name (lo)", why_iface is None, str(why_iface))
        if why_iface is None:
            iface_addrs = [a for a in api.services_addresses(service_id) if a["ip_int"] == "lo"]
            check("interface address is listed", len(iface_addrs) == 1)
            if iface_addrs:
                check("remove interface address", api.services_delete_address(service_id, iface_addrs[0]["address_id"]))

        # --- a filter whose protocol is read off its own code -----------------
        # The file asks for an HttpRequest, which is what makes it an HTTP filter. The
        # service is plain TCP: the two are different questions, and confusing them is
        # what used to make this a 500.
        check("attach a second pyfilter", api.services_add_filter(service_id, "pyfilter", "http"))
        http_filter = [f["filter_id"] for f in api.services_filters(service_id)
                       if f["name"] == "http"][0]
        # --- the code is checked before it is accepted -----------------------
        # By the process that will run it, so what is accepted here is what loads there.
        # The point of the position is that the operator is not told "worker exited" and
        # left to find the line in a traceback in the service log.
        broken = api.services_check_code(service_id, http_filter,
                                         "from firegex.pyfilters import pyfilter\n"
                                         "\n"
                                         "@pyfilter\n"
                                         "def no_annotation(packet):\n"
                                         "    return None\n")
        check("code that cannot load is refused with the line it fails on",
              broken["ok"] is False and broken["error"]["line"] == 4
              and "annotation" in broken["error"]["message"], str(broken))
        syntax = api.services_check_code(service_id, http_filter, "def broken(:\n    pass\n")
        check("a syntax error is reported where it is",
              syntax["ok"] is False and syntax["error"]["type"] == "SyntaxError"
              and syntax["error"]["line"] == 1, str(syntax))
        why = api.services_set_code_error(service_id, http_filter, "def broken(:\n")
        check("and saving it is refused, saying so rather than 'worker exited'",
              why is not None and "SyntaxError" in why and "line 1" in why, str(why))

        good = api.services_check_code(service_id, http_filter, HTTP_PYFILTER_CODE)
        check("code that loads says what it defines and what it speaks",
              good["ok"] is True and good["proto"] == "http"
              and set(good["filters"]) == {"refuse_traversal", "look_at_the_bytes"},
              str(good))

        check("code asking for parsed HTTP is accepted on a TCP service",
              api.services_set_code(service_id, http_filter, HTTP_PYFILTER_CODE))
        detected = [f for f in api.services_filters(service_id)
                    if f["filter_id"] == http_filter][0]
        check("and its protocol was read off the code, not chosen",
              detected["proto"] == "http", str(detected))
        time.sleep(1)
        if not args.tls:
            check("an HTTP request it objects to is refused",
                  not server.sendCheckData(
                      b"GET /../../etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n"))
            check("an HTTP request it does not object to gets through",
                  gets_through(server, b"GET /shop HTTP/1.1\r\nHost: x\r\n\r\n"))

        # --- the functions inside that file, one at a time --------------------
        # A file holds several @pyfilter functions. The code says which exist; the
        # operator says which run. Switching one off must stop it deciding, without the
        # code being edited — deleting a function to silence it and pasting it back to
        # resume is exactly what these switches replace.
        fns = api.services_functions(service_id, http_filter)
        check("every function the file defines is listed",
              {f["name"] for f in fns} == {"refuse_traversal", "look_at_the_bytes"}, str(fns))
        check("and they arrive switched on", all(f["active"] for f in fns), str(fns))
        # In the order the file defines them, which is the order they run in. The list
        # used to be sorted by name, over a run order that was a set's iteration order,
        # so neither the operator nor the file could say which function saw a chunk
        # first — and the first one to refuse is the one that ends it.
        defined_order = [
            line.split("def ", 1)[1].split("(", 1)[0]
            for line in HTTP_PYFILTER_CODE.splitlines() if line.startswith("def ")
        ]
        check("listed in the order the file defines them",
              [f["name"] for f in fns] == defined_order,
              str(([f["name"] for f in fns], defined_order)))
        if not args.tls:
            check("the block was counted against the function that made it",
                  any(f["name"] == "refuse_traversal" and f["blocked"] >= 1 for f in fns),
                  str(fns))

        check("switch one function off",
              api.services_edit_function(service_id, http_filter, "refuse_traversal", False))
        listed = api.services_filters(service_id)
        card = [f for f in listed if f["filter_id"] == http_filter][0]
        check("the chain reports how many are left on",
              card["n_functions"] == 2 and card["n_functions_active"] == 1, str(card))
        time.sleep(1)
        if not args.tls:
            # The other function is still in the file and still running; this one is
            # simply no longer consulted.
            check("the switched-off function no longer refuses anything",
                  gets_through(server,
                               b"GET /../../etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n"))

        check("switch it back on",
              api.services_edit_function(service_id, http_filter, "refuse_traversal", True))
        time.sleep(1)
        if not args.tls:
            check("and it decides again",
                  not server.sendCheckData(
                      b"GET /../../etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n"))

        # The code is what decides which functions exist, so replacing it drops the ones
        # that have gone — while what the operator set for the survivors stays set.
        api.services_edit_function(service_id, http_filter, "look_at_the_bytes", False)
        check("saving different code reconciles the list",
              api.services_set_code(service_id, http_filter, PYFILTER_CODE))
        fns = api.services_functions(service_id, http_filter)
        check("the functions that are gone from the code are gone from the list",
              {f["name"] for f in fns} == {"refuse_marker"}, str(fns))

        check("remove it again", api.services_delete_filter(service_id, http_filter))

        # --- the live log -----------------------------------------------------
        # It has to name what refused the connection. An operator reading an opaque id
        # mid-round learns nothing, which is the same as having no log.
        entries = api.services_logs(service_id)
        check("the log records the start", any(
            e["level"] == "info" and "started on the" in e["text"] for e in entries), str(entries[:3]))
        blocks = [e for e in entries if e["level"] == "block"]
        check("the log names what refused the connection",
              any("BLOCKME" in e["text"] for e in blocks), str(blocks[:3]))
        check("the log is bounded", len(entries) <= 500, str(len(entries)))

        # --- editing under traffic --------------------------------------------
        check("add a pattern to a running service",
              api.services_add_regex(service_id, regex_filter, "SECOND", mode="B"))
        time.sleep(0.5)
        if not args.tls:
            check("the new pattern is already in force",
                  not server.sendCheckData(b"carrying SECOND"))

        before = api.services_logs(service_id)
        check("clearing the log", api.services_clear_logs(service_id))
        # Not "empty": the service is still running, and a line arriving a millisecond
        # later belongs in the log. What has to be gone is everything from before.
        after = api.services_logs(service_id)
        oldest_kept = min((e["seq"] for e in after), default=None)
        check("clearing drops what came before",
              len(after) < len(before)
              and (oldest_kept is None or oldest_kept > max(e["seq"] for e in before)),
              f"{len(before)} -> {len(after)}")



        # --- ALPN is the service's answer, carried, not the proxy's ------------
        # Terminating in the middle of a connection means answering for a service, and
        # answering something the service did not say is how a proxy breaks a protocol it
        # was only supposed to carry: a client told `h2` while the service speaks
        # HTTP/1.1 sends frames to something that cannot read them. So the ClientHello is
        # held open, the service is asked with exactly the client's list, and the client
        # is told exactly what came back — including "nothing".
        if args.tls:
            for offers, speaks, expected, why in (
                (["h2", "http/1.1"], ["h2", "http/1.1"], "h2", "both ends want h2"),
                (["h2", "http/1.1"], ["http/1.1"], "http/1.1",
                 "the service does not speak h2, so neither does the client"),
                (["h2"], ["http/1.1"], None,
                 "nobody agrees, and the proxy does not invent an agreement"),
                (["h2", "http/1.1"], None, None, "the service offers no ALPN at all"),
            ):
                alpn_port = args.port + 13
                alpn_server = TcpServer(alpn_port, args.ipv6, tls_cert=cert, tls_key=key,
                                        tls_alpn=speaks)
                alpn_server.start()
                alpn_id = api.services_add(f"{name}-alpn", ip, alpn_port, args.transport,
                                           tls=True, tls_cert=cert, tls_key=key)
                try:
                    api.services_start(alpn_id)
                    time.sleep(1.5)
                    got = tls_alpn_choice(alpn_port, args.ipv6, offers)
                    check(f"ALPN: {why}", got == expected, f"got {got!r}, wanted {expected!r}")
                finally:
                    if alpn_id:
                        api.services_stop(alpn_id)
                        api.services_delete(alpn_id)
                    alpn_server.stop()
                    time.sleep(0.8)

        # --- a key too small for the engine is refused, and says why ------------
        # nginx could be told to take an under-2048-bit RSA key with @SECLEVEL=1. rustls
        # has no equivalent: its signing backend refuses such a key outright, so a
        # service carrying one cannot be decrypted here at all. What matters is that the
        # operator is told that, rather than being handed "the engine did not report a
        # listening port" and left to find the reason in a container log.
        if args.tls:
            weak_port = args.port + 9
            weak_cert, weak_key = generate_self_signed_cert_key(ip, key_size=1024)
            weak = api.services_add(f"{name}-wk", ip, weak_port, args.transport,
                                    tls=True, tls_cert=weak_cert, tls_key=weak_key)
            check("a service with a 1024-bit certificate can be created", weak is not None)
            try:
                refused = api.services_start_error(weak)
                check("but will not start, carrying the engine's own reason",
                      refused is not None and "key" in str(refused).lower(), str(refused))
            finally:
                if weak:
                    api.services_delete(weak)
                time.sleep(0.5)

        # --- one broken TLS service is one broken TLS service -------------------
        # It used to be able to take every other one down with it: nginx parses its
        # configuration as a unit and refuses to start if any one `ssl_certificate` will
        # not load, so a service whose material was damaged left every TLS service on the
        # instance refusing connections on ports that had been working. Each service now
        # carries its certificate into its own engine process, so the blast radius is
        # structural rather than something that has to be arranged — which is worth a
        # test precisely because nothing in the code says so any more.
        if args.tls:
            good_port, bad_port = args.port + 5, args.port + 7
            neighbour = TcpServer(good_port, args.ipv6, tls_cert=cert, tls_key=key)
            neighbour.start()
            good = api.services_add(f"{name}-ok", ip, good_port, args.transport,
                                    tls=True, tls_cert=cert, tls_key=key)
            bad = api.services_add(f"{name}-brk", ip, bad_port, args.transport)
            check("a working TLS service and one to break", good and bad)
            try:
                refusal = api.services_edit_error(bad, proto="tls")
                check("switching to TLS with nothing stored is refused",
                      refusal is not None, str(refusal))
                # Forced past that refusal the only way left: material whose envelope is
                # right and whose body will not parse. The envelope check cannot judge
                # this one, so it is the engine that has to say so.
                api.services_edit(bad, proto="tls",
                                  tls_cert="-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n",
                                  tls_key="-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----\n")
                check("the working one starts", api.services_start(good))
                refused = api.services_start_error(bad)
                check("the broken one refuses to start, with the engine's reason",
                      refused is not None
                      and ("certificate" in str(refused).lower() or "key" in str(refused).lower()),
                      str(refused))
                time.sleep(1.5)
                got = tls_connect_send_recv(good_port, args.ipv6, b"harmless traffic")
                check("and its neighbour is still serving",
                      got == b"harmless traffic", repr(got))
            finally:
                for sid in (good, bad):
                    if sid:
                        api.services_stop(sid)
                        api.services_delete(sid)
                neighbour.stop()
                time.sleep(1)

        if args.transport == "proxy":
            # --- the connection limit, and the trace it leaves ----------------------
            # The attack this exists for was measured before it did: connections that are
            # opened and then say nothing cost two descriptors each — one from the client,
            # one to the service, because the upstream is dialled on accept — and about 505
            # of them exhausted the container and took *every* service down. The limit does
            # not save the service being attacked, because a cap cannot tell a phantom from
            # a client; it stops one service's attacker from being everyone's.
            # The proxy layer only: it is the one that accepts connections and dials the
            # service, which is what a limit counts. NFQUEUE hands the kernel a verdict on
            # packets already in flight.
            limited_port = args.port + 11
            limited_server = TcpServer(limited_port, args.ipv6)
            limited_server.start()
            limited = api.services_add(f"{name}-cap", ip, limited_port, args.transport,
                                       max_connections=4)
            check("a service with a connection limit", limited is not None)
            try:
                check("starts", bool(limited) and api.services_start(limited))
                time.sleep(1.5)
                listed = [s for s in api.services_list() if s["service_id"] == limited][0]
                check("reports its limit", listed["max_connections"] == 4, str(listed))
                check("and has turned nothing away yet", listed["over_limit_hits"] == 0, str(listed))

                phantoms = []
                for _ in range(12):
                    try:
                        phantoms.append(socket.create_connection(
                            ("::1" if args.ipv6 else "127.0.0.1", limited_port), timeout=3))
                    except OSError:
                        break
                time.sleep(3)
                listed = [s for s in api.services_list() if s["service_id"] == limited][0]
                check("the limit turns away what does not fit",
                      listed["over_limit_hits"] > 0, str(listed["over_limit_hits"]))
                # The trace, which is the point: the live log is a bounded ring, so a burst
                # at three in the morning would be gone by breakfast.
                check("and says when it first and last happened",
                      listed["over_limit_first"] is not None and listed["over_limit_last"] is not None,
                      str(listed))
                check("the log warns about it too",
                      any("limit" in e["text"].lower() for e in api.services_logs(limited)),
                      str([e["text"] for e in api.services_logs(limited)][-3:]))
                for phantom in phantoms:
                    phantom.close()
                time.sleep(1.5)
                was = listed["over_limit_hits"]
                api.services_stop(limited)
                api.services_start(limited)
                time.sleep(1.5)
                listed = [s for s in api.services_list() if s["service_id"] == limited][0]
                check("and the count outlives the engine that made it",
                      listed["over_limit_hits"] >= was,
                      f'{was} -> {listed["over_limit_hits"]}')
                # --- and what the limit alone cannot do -------------------------
                # A cap contains the damage; it cannot tell a connection that is silent
                # because it is an attack from one that is silent because the client is
                # slow, so an attacker who fills it keeps it filled. A deadline on the
                # *first* byte can: the slots come back while the attacker is still
                # holding the sockets.
                api.services_edit(limited, first_byte_timeout=3)
                time.sleep(2)
                held = []
                for _ in range(8):
                    try:
                        held.append(socket.create_connection(
                            ("::1" if args.ipv6 else "127.0.0.1", limited_port), timeout=3))
                    except OSError:
                        break
                time.sleep(1)
                check("with the limit full, a client cannot get in",
                      not gets_through(limited_server, b"knock knock"))
                time.sleep(5)
                check("but the deadline frees the slots while the attacker still holds them",
                      gets_through(limited_server, b"knock knock"))
                for phantom in held:
                    phantom.close()
            finally:
                if limited:
                    api.services_stop(limited)
                    api.services_delete(limited)
                limited_server.stop()
                time.sleep(1)

        # --- UDP, on whichever layer this run is exercising ---------------------
        # Both carry it, and the same filters work on both — which is the whole point of
        # the model. They get there differently: the proxy relays datagrams with one
        # socket per address (the kernel option that recovers a TCP connection's original
        # destination is TCP-only, so there is nothing to recover per datagram), while
        # nfqueue inspects the real datagram in place. What the proxy gives up is the
        # client's address; what both keep is exact rewriting, because a datagram has no
        # sequence numbers to desynchronise.
        if args.transport in ("proxy", "nfqueue") and not args.tls:
            udp_port = args.port + 3
            echo = UdpEcho(udp_port, args.ipv6)
            echo.start()
            udp_id = api.services_add(f"{name}-udp", ip, udp_port, args.transport, proto="udp")
            check(f"a UDP service on the {args.transport} layer can be created",
                  udp_id is not None)
            try:
                api.services_add_filter(udp_id, "regex", "patterns")
                ufid = api.services_filters(udp_id)[0]["filter_id"]
                api.services_add_regex(udp_id, ufid, "DENYME", mode="B")
                check("and it starts", api.services_start(udp_id))
                time.sleep(1.2)

                check("a benign datagram is relayed and answered",
                      echo.exchange(b"hello there") == b"hello there")
                check("a matching datagram is refused", echo.exchange(b"carrying DENYME") is None)
                # Nothing was closed — UDP has no connection to close — so the same flow
                # keeps working for the datagrams that are not refused.
                check("the flow survives a refused datagram",
                      echo.exchange(b"still here") == b"still here")

                time.sleep(0.5)
                rows = api.services_regexes(udp_id, ufid)
                check("the block is counted against the pattern",
                      any(r["blocked"] >= 1 for r in rows), str(rows))

                # --- a second UDP address on the running service -------------
                echo2 = UdpEcho(udp_port + 1, args.ipv6)
                echo2.start()
                try:
                    why = api.services_add_address_error(udp_id, ip, udp_port + 1)
                    check("protect a second UDP address without restarting", why is None, str(why))
                    time.sleep(1)
                    check("benign datagram to the new UDP address gets through",
                          echo2.exchange(b"hello second") == b"hello second")
                    check("the same chain filters the new UDP address",
                          echo2.exchange(b"carrying DENYME") is None)
                    entries = api.services_logs(udp_id)
                    check("the log says the UDP address was added without dropping anything",
                          any("also protecting" in e["text"] for e in entries), str(entries[-4:]))
                    gone_udp = [a for a in api.services_addresses(udp_id)
                                if a["port"] == udp_port + 1][0]["address_id"]
                    check("remove second UDP address", api.services_delete_address(udp_id, gone_udp))
                finally:
                    echo2.stop()

                # --- a Python filter on UDP ----------------------------------
                # It works on datagrams, and the models that need a stream underneath
                # are refused rather than accepted and never called.
                api.services_stop(udp_id)
                api.services_add_filter(udp_id, "pyfilter", "datagrams")
                upf = [f for f in api.services_filters(udp_id)
                       if f["kind"] == "pyfilter"][0]["filter_id"]
                why = api.services_set_code_error(udp_id, upf, HTTP_PYFILTER_CODE)
                check("a filter needing a TCP stream is refused on a UDP service",
                      why is not None and "UDP" in why and "HttpRequest" in why, str(why))
                check("one written against RawPacket is accepted",
                      api.services_set_code(udp_id, upf, UDP_PYFILTER_CODE))
                check("and the service starts with it", api.services_start(udp_id))
                time.sleep(1.2)
                check("a datagram it objects to is dropped",
                      echo.exchange(b"carrying PYDENY") is None)
                check("and one it does not is delivered",
                      echo.exchange(b"perfectly fine") == b"perfectly fine")
                time.sleep(0.6)
                fns = api.services_functions(udp_id, upf)
                check("the block is counted against the function that made it",
                      any(f["blocked"] >= 1 for f in fns), str(fns))
            finally:
                api.services_stop(udp_id)
                api.services_delete(udp_id)
                echo.stop()

    except SystemExit:
        pass  # the external transport finishes early, on purpose
    finally:
        if service_id:
            api.services_stop(service_id)
            api.services_delete(service_id)
        if server:
            server.stop()
        if external:
            external.stop()

    sep()
    puts("Passed" if exit_code == 0 else "Failed",
         color=colors.green if exit_code == 0 else colors.red, is_bold=True)
    exit(exit_code)
