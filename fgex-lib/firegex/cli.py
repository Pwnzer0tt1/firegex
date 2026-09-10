
#!/usr/bin/env python3

import json
import os
import socket
import sys

import typer
from rich import print
from rich.markup import escape
from typer import Exit

from firegex import __version__
from firegex.pyfilters.proxysim import run_proxy_simulation

app = typer.Typer(
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]}
)

def close_cli(code:int=1):
    raise Exit(code)

DEV_MODE = __version__ == "0.0.0"

def test_connection(host, port, use_ipv6=False):
    family = socket.AF_INET6 if use_ipv6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    
    try:
        sock.settimeout(3)
        sock.connect((host, port))
        return True
    except Exception:
        return False
    finally:
        sock.close()

@app.command("pyfilters", help="Run your Python filters against a real service, locally")
# `nfproxy` is what this was called when it was one of several modules. Kept as a second
# name rather than removed: it is in people's shell history and in scripts, and a command
# that has quietly stopped existing is a worse answer than one that still works.
@app.command("nfproxy", hidden=True)
def pyfilters(
    filter_file: str = typer.Argument(..., help="The path to the filter file"),
    address: str = typer.Argument(..., help="The address of the target to proxy"),
    port: int = typer.Argument(..., help="The port of the target to proxy"),
    
    from_address: str = typer.Option(None, help="The address of the local server"),
    from_port: int = typer.Option(7474, help="The port of the local server"),    
    ipv6: bool = typer.Option(False, "-6", help="Use IPv6 for the connection"),
):
    if from_address is None:
        from_address = "::1" if ipv6 else "127.0.0.1"
    if not os.path.isfile(filter_file):
        print(f"[bold red]'{escape(os.path.abspath(filter_file))}' not found[/]")
        close_cli()
    if not test_connection(address, port, ipv6):
        print(f"[bold red]Can't connect to {escape(address)}:{port}[/]")
        close_cli()
    # No protocol to pass: the filter file says which one it speaks by what it asks for.
    run_proxy_simulation(filter_file, address, port, from_address, from_port, ipv6)

regex_app = typer.Typer(
    no_args_is_help=True,
    help="Try a regex ruleset with the engine firegex matches with",
)
app.add_typer(regex_app, name="regex")


def _load_ruleset(path: str):
    """Read a ruleset, with the errors an operator can act on.

    The file is the same shape firegex itself uses, so a ruleset can be written here and
    pasted there, or exported from there and replayed here.
    """
    from firegex.regex import HyperscanMissing, Rule, available, validate

    if not available():
        print(f"[bold red]{escape(str(HyperscanMissing()))}[/]")
        close_cli()
    if not os.path.isfile(path):
        print(f"[bold red]'{escape(os.path.abspath(path))}' not found[/]")
        close_cli()
    try:
        with open(path) as f:
            raw = json.load(f)
    except json.JSONDecodeError as e:
        print(f"[bold red]{escape(path)} is not valid JSON: {escape(str(e))}[/]")
        close_cli()
    if not isinstance(raw, list):
        print("[bold red]A ruleset is a list of rules[/]")
        close_cli()

    rules = []
    broken = False
    for index, item in enumerate(raw):
        try:
            rule = Rule.from_dict(item)
        except (KeyError, ValueError) as e:
            print(f"[bold red]rule {index} is malformed: {escape(str(e))}[/]")
            broken = True
            continue
        # Judged against the mode it would actually run in, so what is accepted here is
        # what firegex will accept.
        why = validate(rule)
        if why:
            print(f"[bold red]{escape(rule.id)}: {escape(why)}[/]")
            broken = True
            continue
        rules.append(rule)
    if broken:
        close_cli()
    if not rules:
        print("[bold red]The ruleset is empty[/]")
        close_cli()
    return rules


@regex_app.command("check", help="Check that a ruleset compiles, and say what is in it")
def regex_check(
    rules_file: str = typer.Argument(..., help="The path to the ruleset (JSON)"),
):
    rules = _load_ruleset(rules_file)
    print(f"[bold green]{len(rules)} rule(s), all valid[/]")
    for rule in rules:
        case = "" if rule.case_sensitive else ", any case"
        print(f"  [bold]{escape(rule.id)}[/]  /{escape(rule.pattern)}/  "
              f"[dim]{rule.direction.value}{case}, block[/]")


@regex_app.command("test", help="Run a ruleset over a sample and show what it would do")
def regex_test(
    rules_file: str = typer.Argument(..., help="The path to the ruleset (JSON)"),
    sample_file: str = typer.Option(None, "--sample", "-s",
                                    help="File to match against; stdin when omitted"),
    from_service: bool = typer.Option(False, "--from-service",
                                      help="Treat the sample as traffic from the service"),
):
    from firegex.regex import Ruleset

    rules = _load_ruleset(rules_file)
    if sample_file:
        if not os.path.isfile(sample_file):
            print(f"[bold red]'{escape(os.path.abspath(sample_file))}' not found[/]")
            close_cli()
        with open(sample_file, "rb") as f:
            sample = f.read()
    else:
        sample = sys.stdin.buffer.read()
    if not sample:
        print("[bold red]Nothing to match against[/]")
        close_cli()

    ruleset = Ruleset(rules)
    is_input = not from_service
    blocked_by, payload = ruleset.apply(sample, is_input)

    if blocked_by is not None:
        print(f"[bold red]blocked[/] by [bold]{escape(blocked_by)}[/]")
        close_cli(0)
    if payload != sample:
        print("[bold yellow]rewritten[/]")
        print(escape(payload.decode(errors="replace")))
        close_cli(0)
    print("[bold green]passed through unchanged[/]")


@regex_app.command("proxy", help="Run a local proxy applying a ruleset, like `fgex pyfilters`")
def regex_proxy(
    rules_file: str = typer.Argument(..., help="The path to the ruleset (JSON)"),
    address: str = typer.Argument(..., help="The address of the target to proxy"),
    port: int = typer.Argument(..., help="The port of the target to proxy"),
    from_address: str = typer.Option(None, help="The address of the local server"),
    from_port: int = typer.Option(7474, help="The port of the local server"),
    ipv6: bool = typer.Option(False, "-6", help="Use IPv6 for the connection"),
):
    from firegex.regex import Ruleset
    from firegex.regex.sim import run_regex_simulation

    rules = _load_ruleset(rules_file)
    if from_address is None:
        from_address = "::1" if ipv6 else "127.0.0.1"
    if not test_connection(address, port, ipv6):
        print(f"[bold red]Can't connect to {escape(address)}:{port}[/]")
        close_cli()
    print("[dim]Blocking matches per chunk here, but across the whole stream on a real "
          "service: a pattern split over two reads is caught there and not here.[/]")
    run_regex_simulation(Ruleset(rules), address, port, from_address, from_port, ipv6)


def version_callback(verison: bool):
    if verison:
        print(__version__, "Development Mode" if DEV_MODE else "Release")
        raise typer.Exit()

@app.callback()
def main(
    verison: bool = typer.Option(False, "--version", "-v", help="Show the version of the client", callback=version_callback),
):
    pass

def run():
    try:
        app()
    except KeyboardInterrupt:
        print("[bold yellow]Operation cancelled[/]") 
 
if __name__ == "__main__":
    run()
