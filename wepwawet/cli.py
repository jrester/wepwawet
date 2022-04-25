import logging
import shlex
from threading import Event
from typing import List

import click
from wepwawet.config import Config, VPNType
from wepwawet.policies import ProcessPolicy
from wepwawet.utils import find_free_table_name, find_free_netns_name
from wepwawet.wepwawet import Wepwawet
from wepwawet.wireguard import Wireguard

logger = logging.getLogger("wepwawet")
logging.basicConfig(format="%(asctime)s | %(levelname)s | %(message)s")


def err(msg):
    click.secho(msg, fg="red", err=True)
    exit(1)


def _load_config(config_file):
    try:
        config = Config.from_file(config_file)
    except FileNotFoundError:
        err(f"file {config_file} does not exist")
    except ValueError as e:
        err(f"{config_file} is invallid: {e}")
    return config


@click.group()
@click.option("--config-file", "-c", default=None, help="Path to config file")
@click.option("--log-level", default="ERROR", help="Log level")
@click.option("--interface", "-i", default=None, help="Interface to use")
@click.option(
    "--table-name",
    "-t",
    default=find_free_table_name(table_start=10111),
    help="Table name",
)
@click.option("--ipv6/--no-ipv6", default=False, help="Enable/Disable IPv6")
@click.option(
    "--killswitch", "-k", default=False, help="Enable killswitch", is_flag=True
)
@click.option(
    "--net",
    default=[],
    multiple=True,
    help="Networks which won't be routed over the VPN",
)
@click.pass_context
def cli(
    ctx,
    config_file: str,
    log_level: str,
    interface: str,
    table_name: int,
    ipv6: bool,
    killswitch: bool,
    net: List[str],
):
    if config_file is None and interface is None:
        err("--config-file or --interface must be specified")
    elif config_file is not None and interface is not None:
        err("--config-file and --interface cannot be specified together")
    logger.setLevel(logging.getLevelName(log_level))
    if config_file is not None:
        config = _load_config(config_file)
    else:
        config = Config(
            table_name=table_name,
            interface=interface,
            policies=[],
            vpn=None,
            ipv6=ipv6,
            nets=net,
        )
    ctx.obj = config


@click.command()
@click.pass_obj
def run(config):
    if config.vpn is None:
        err("can't use 'run' without --config-file")
    if config.vpn["type"] == VPNType.WIREGUARD.value:
        cls = Wireguard
    else:
        err("Currently only wireguard is supported")

    with cls.from_config(config):
        with Wepwawet.from_config(config):
            evt = Event()
            evt.wait()


@click.command()
@click.argument("cmd")
@click.pass_obj
def exec(config: Config, cmd: str):
    cmd_parts = shlex.split(cmd)
    config.policies = [
        ProcessPolicy(cmd_parts, ns_name=find_free_netns_name(), ipv6=config.ipv6)
    ]

    if config.vpn is not None:
        if config.vpn["type"] == VPNType.WIREGUARD.value:
            cls = Wireguard
        else:
            err("Currently only wireguard is supported")

        with cls.from_config(config):
            with Wepwawet.from_config(config) as w:
                w.action()
    else:
        with Wepwawet.from_config(config) as w:
            w.action()


@click.group()
def config():
    pass


@click.command()
def validate():
    click.secho("config file is valid", fg="green")


config.add_command(validate)

cli.add_command(run)
cli.add_command(exec)
cli.add_command(config)
