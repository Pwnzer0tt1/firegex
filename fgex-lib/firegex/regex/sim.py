"""A local proxy that applies a regex ruleset, for trying one before it goes live.

The counterpart of `firegex.pyfilters.proxysim` for patterns: point it at your service,
send traffic through it, and see what a ruleset would do. It matches with the same
hyperscan the datapath matches with, so a pattern that blocks here blocks there.

One difference it cannot paper over, and says out loud: a *blocking* rule on a real
service matches across the whole stream, while this matches each chunk on its own. A
pattern split over two reads is caught in production and not here — never the other way
round, so this errs towards showing you less than will actually happen.
"""

import asyncio
import socket

from rich import print
from rich.markup import escape

from firegex.regex import Ruleset


def _log(module: str, message: str, level: str = "INFO"):
    colour = {"INFO": "blue", "WARNING": "yellow", "ERROR": "red"}.get(level, "blue")
    print(f"[bold {colour}][{level}][/] [bold]\\[{escape(module)}][/] {message}")


async def _pump(rules: Ruleset, reader, writer, is_input: bool, on_block):
    """Move one direction, applying the ruleset to every chunk."""
    try:
        while True:
            try:
                data = await reader.read(4096)
            except Exception:
                break
            if not data:
                break
            try:
                blocked_by, payload = rules.apply(data, is_input)
            except Exception as e:
                # A ruleset that blows up mid-connection must not take the traffic with
                # it; the real datapath fails open too, and so does this.
                _log("filter", f"failed on this chunk ({escape(str(e))}), forwarding it", "ERROR")
                blocked_by, payload = None, data
            if blocked_by is not None:
                on_block(blocked_by)
                _log("block", f"connection refused by [bold]{escape(blocked_by)}[/]", "WARNING")
                break
            if payload != data:
                _log("rewrite", f"{escape(repr(data)[:60])} -> {escape(repr(payload)[:60])}")
            writer.write(payload)
            await writer.drain()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def _handle(reader, writer, rules: Ruleset, target_ip: str, target_port: int,
                  ipv6: bool, counters: dict):
    peer = writer.get_extra_info("peername")
    _log("listener", f"accepted {escape(str(peer[0]))}:{peer[1]}")
    try:
        remote_reader, remote_writer = await asyncio.open_connection(
            target_ip, target_port, family=socket.AF_INET6 if ipv6 else socket.AF_INET
        )
    except Exception as e:
        _log("listener", f"cannot reach {escape(target_ip)}:{target_port}: {escape(str(e))}", "ERROR")
        writer.close()
        return

    def on_block(rule_id: str):
        counters[rule_id] = counters.get(rule_id, 0) + 1

    await asyncio.gather(
        _pump(rules, reader, remote_writer, True, on_block),
        _pump(rules, remote_reader, writer, False, on_block),
    )
    remote_writer.close()


async def _serve(rules: Ruleset, target_ip: str, target_port: int,
                 local_ip: str, local_port: int, ipv6: bool, counters: dict):
    server = await asyncio.start_server(
        lambda r, w: _handle(r, w, rules, target_ip, target_port, ipv6, counters),
        local_ip, local_port, family=socket.AF_INET6 if ipv6 else socket.AF_INET,
    )
    _log("listener",
         f"listening on [bold]{escape(local_ip)}:{local_port}[/] "
         f"and forwarding to [bold]{escape(target_ip)}:{target_port}[/]")
    async with server:
        await server.serve_forever()


def run_regex_simulation(rules: Ruleset, target_ip: str, target_port: int,
                         local_ip: str, local_port: int, ipv6: bool = False):
    counters: dict[str, int] = {}
    try:
        asyncio.run(_serve(rules, target_ip, target_port, local_ip, local_port, ipv6, counters))
    except KeyboardInterrupt:
        _log("listener", "stopped", "WARNING")
        if counters:
            print()
            for rule_id, count in sorted(counters.items(), key=lambda kv: -kv[1]):
                print(f"  [bold]{escape(rule_id)}[/] refused {count} connection(s)")
