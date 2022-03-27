import logging
from threading import Event

import click
from wepwawet.config import Config, VPNType
from wepwawet.wepwawet import Wepwawet, Wireguard

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
def cli():
    pass


@click.command()
@click.option("--config-file", default="config.yaml", help="Path to config file")
@click.option("--log-level", default="INFO", help="Log level")
@click.option(
    "--standalone",
)
def run(config_file, log_level):
    config = _load_config(config_file)
    logger.setLevel(logging.getLevelName(log_level))

    if config.vpn["type"] == VPNType.WIREGUARD.value:
        cls = Wireguard
    else:
        err("Currently only wireguard is supported")

    with cls.from_config(config):
        with Wepwawet.from_config(config):
            evt = Event()
            evt.wait()


@click.group()
def config():
    pass


@click.command()
@click.option("--config-file", default="config.yaml", help="Path to config file")
def validate(config_file):
    _load_config(config_file)
    click.secho(f"{config_file} is valid", fg="green")


config.add_command(validate)

cli.add_command(run)
cli.add_command(config)