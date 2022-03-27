import ipaddress
import logging
import socket
from typing import List

import pyroute2
from wepwawet.config import Config
from wepwawet.policies import RoutingPolicy

logger = logging.getLogger("wepwawet")


class Wepwawet:
    def __init__(
        self,
        table_name,
        interface,
        routing_policies: List[RoutingPolicy],
        ipv6: bool = True,
    ):
        self._table_name = table_name
        self.interface = interface
        self.routing_policies = routing_policies
        self.ipv6 = ipv6
        self.ipr = pyroute2.IPRoute()

    @staticmethod
    def from_config(config: Config) -> "Wepwawet":
        return Wepwawet(
            config.table_name, config.interface, config.policies, config.ipv6
        )

    def _add_to_list_if_not_already_in_subnet(self, subnet, local_networks):
        """add the subnet to the list of local_networks if it is not a subnet or supernet of an existing local network"""
        new_subnet = ipaddress.ip_network(subnet["dst"])
        for local_network in local_networks:
            local_net = ipaddress.ip_network(local_network["dst"])
            if new_subnet.version == local_net.version:
                if local_net.supernet_of(new_subnet):
                    return
                elif local_net.subnet_of(new_subnet):
                    local_networks.remove(local_network)
                    local_networks.append(subnet)
                    return

        local_networks.append(subnet)

    def _get_local_networks(self) -> List[dict]:
        local_networks = []
        for route in self.ipr.get_routes():
            dst = route.get_attr("RTA_DST")
            if dst is None:
                continue

            net = f"{dst}/{route['dst_len']}"
            if ipaddress.ip_network(net).is_private:
                res = {"dst": net}
                oif = route.get_attr("RTA_OIF")
                gw = route.get_attr("RTA_GATEWAY")

                if oif is None and gw is None:
                    continue

                if oif:
                    res["oif"] = oif
                else:
                    res["gw"] = gw

                self._add_to_list_if_not_already_in_subnet(res, local_networks)

        return local_networks

    def _clean_up(self):
        self.ipr.flush_rules(table=self._table_name)
        self.ipr.flush_rules(table=self._table_name, family=socket.AF_INET6)
        self.ipr.flush_routes(table=self._table_name)
        self.ipr.flush_routes(table=self._table_name, family=socket.AF_INET6)

    def _apply_routing_policies(self):
        for policy in self.routing_policies:
            policy.up(self.ipr, self._table_name)

    def _create_routing_tables(self):
        self._apply_routing_policies()

        iface_idx = self.ipr.link_lookup(ifname=self.interface)[0]
        self.ipr.route(
            "add",
            table=self._table_name,
            dst="default",
            oif=iface_idx,
            metrics={"attrs": [["RTAX_PRIORITY", 0]]},
        )
        if self.ipv6:
            self.ipr.route(
                "add",
                table=self._table_name,
                dst="default",
                oif=iface_idx,
                metrics={"attrs": [["RTAX_PRIORITY", 100]]},
                family=socket.AF_INET6,
            )
        else:
            # block all ipv6 traffic
            self.ipr.route("add", table=self._table_name, dst="::0/0", type="prohibit")

        for local_network in self._get_local_networks():
            family = socket.AF_INET
            if isinstance(
                ipaddress.ip_network(local_network["dst"]), ipaddress.IPv6Network
            ):
                if not self.ipv6:
                    continue
                family = socket.AF_INET6

            self.ipr.route(
                "add", table=self._table_name, family=family, **local_network
            )

        logger.info("Created routing tables")

    def up(self):
        try:
            self._clean_up()
        except Exception:
            pass

        self._create_routing_tables()

    def down(self):
        self._clean_up()

    def __enter__(self):
        self.up()
        return self

    def __exit__(self, _type, _value, _traceback):
        self.down()
