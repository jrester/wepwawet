import ipaddress
import logging
import socket

import pyroute2
from wepwawet.config import Config

logger = logging.getLogger("wepwawet")


class Wireguard:
    def __init__(self, interface, config: dict):
        self.interface = interface
        self.config = config
        self.wg = pyroute2.WireGuard()

    @staticmethod
    def from_config(config: Config):
        return Wireguard(config.interface, config.vpn)

    def up(self):
        try:
            self._clean_up()
        except Exception:
            pass

        logger.info("Creating Wireguard interface")

        with pyroute2.IPRoute() as ipr:
            ipr.link("add", ifname=self.interface, kind="wireguard")
            link_idx = ipr.link_lookup(ifname=self.interface)[0]
            for address in self.config["interface"]["address"]:
                family = socket.AF_INET
                ip_net = ipaddress.ip_network(address)
                if ip_net.version == 6:
                    family = socket.AF_INET6

                ipr.addr(
                    "add",
                    index=link_idx,
                    address=address.split("/")[0],
                    mask=ip_net.prefixlen,
                    family=family,
                )

            ipr.link("set", index=link_idx, state="up")

        peer_config = self.config["peer"]
        endpoint = peer_config["endpoint"].split(":")
        peer = {
            "public_key": peer_config["public_key"],
            "allowed_ips": peer_config["allowed_ips"],
            "endpoint_addr": endpoint[0],
            "endpoint_port": int(endpoint[1]),
            "persistent_keepalive": peer_config["keepalive"],
        }
        if "preshared_key" in peer_config:
            peer["preshared_key"] = peer_config["preshared_key"]

        self.wg.set(
            self.interface,
            private_key=self.config["interface"]["private_key"],
            peer=peer,
        )
        logger.info("Wireguard interface %s up", self.interface)

    def _clean_up(self):
        with pyroute2.IPRoute() as ipr:
            link_idx = ipr.link_lookup(ifname=self.interface)
            if len(link_idx) > 0:
                logger.info("Cleaning up Wireguard interface")
                ipr.link("del", index=link_idx[0])

    def down(self):
        self._clean_up()
        logger.info("Wireguard interface %s down", self.interface)

    def __enter__(self):
        self.up()
        return self

    def __exit__(self, _type, _value, _traceback):
        self.down()
