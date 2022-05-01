from ipaddress import ip_network
import logging
import shlex
from typing import List, Optional

import click
from wepwawet.ipr import IPR
from wepwawet.policies import ProcessPolicy
from wepwawet.utils import find_free_table_name, find_free_netns_name, is_table_in_use

logger = logging.getLogger("wepwawet")
logging.basicConfig(format="%(asctime)s | %(levelname)s | %(message)s")


def err(msg):
    click.secho(msg, fg="red", err=True)
    exit(1)


@click.group()
@click.option("--log-level", default="ERROR", help="Log level")
def cli(
    log_level: str,
):
    logger.setLevel(logging.getLevelName(log_level))


@click.command()
@click.argument("cmd")
@click.option(
    "--table",
    "-t",
    default=None,
    help="ip table",
)
@click.option("--ipv6/--no-ipv6", default=False, help="Enable/Disable IPv6")
@click.option(
    "--killswitch", "-k", default=False, help="Enable killswitch", is_flag=True
)
@click.option(
    "--exclude",
    default=[],
    multiple=True,
    help="Networks which won't be routed over the VPN",
)
@click.option(
    "--net", default=[], multiple=True, help="network to route over the interface"
)
@click.option(
    "--dns", default=[], multiple=True, help="Configure the DNS servers for the process"
)
@click.option("--interface", "-i", default=None, help="Interface to use")
def exec(
    interface: str,
    table: Optional[int],
    ipv6: bool,
    killswitch: bool,
    exclude: List[str],
    net: List[str],
    dns: List[str],
    cmd: str,
):
    cmd_parts = shlex.split(cmd)
    logger.info("running")
    with IPR():
        free_table = (
            table
            if table is not None and not is_table_in_use(table)
            else find_free_table_name(table_start=10111)
        )
        nets = [ip_network(n) for n in net]
        exclude_nets = [ip_network(n) for n in exclude]
        with ProcessPolicy(
            cmd_parts,
            interface=interface,
            table=free_table,
            dns=dns,
            ns_name=find_free_netns_name(),
            killswitch=killswitch,
            nets=nets,
            exclude_nets=exclude_nets,
            ipv6=ipv6,
        ) as p:
            p.action()


cli.add_command(exec)
