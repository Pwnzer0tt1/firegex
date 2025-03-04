
#!/usr/bin/env python3

import typer
from rich import print
from typer import Exit
from firegex import __version__
from firegex.nfproxy.proxysim import run_proxy_simulation
from firegex.nfproxy.models import Protocols

app = typer.Typer(
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]}
)

def close_cli(code:int=1):
    raise Exit(code)

DEV_MODE = __version__ == "0.0.0"

@app.command(help="Run an nfproxy simulation")
def nfproxy(
    filter_file: str = typer.Argument(..., help="The path to the filter file"),
    address: str = typer.Argument(..., help="The address of the target to proxy"),
    port: int = typer.Argument(..., help="The port of the target to proxy"),
    
    proto: Protocols = typer.Option(Protocols.TCP.value, help="The protocol to proxy"),
    from_address: str = typer.Option(None, help="The address of the local server"),
    from_port: int = typer.Option(7474, help="The port of the local server"),    
    ipv6: bool = typer.Option(False, "-6", help="Use IPv6 for the connection"),
):
    if from_address is None:
        from_address = "::1" if ipv6 else "127.0.0.1"
        
    run_proxy_simulation(filter_file, proto.value, address, port, from_address, from_port, ipv6)

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
