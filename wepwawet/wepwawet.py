import logging
import socket
from typing import List

import pyroute2
from wepwawet.config import Config
from wepwawet.policies import RoutingPolicy
from wepwawet.utils import (
    add_iptables_nat_masquerade,
    del_iptables_nat_masquerade,
    get_iface_name_for_idx,
    get_route_for_dst_net,
    IPNetwork,
)

logger = logging.getLogger("wepwawet")


class Wepwawet:
    def __init__(
        self,
        table_name,
        interface,
        routing_policies: List[RoutingPolicy],
        ipv6: bool = True,
        nets: List[IPNetwork] = [],
    ):
        self._table_name = table_name
        self.interface = interface
        self.routing_policies = routing_policies
        self.ipv6 = ipv6
        self.ipr = pyroute2.IPRoute()
        self.exemption_nets = nets

    @staticmethod
    def from_config(config: Config) -> "Wepwawet":
        return Wepwawet(
            config.table_name,
            config.interface,
            config.policies,
            config.ipv6,
            config.nets,
        )

    def _clean_up(self):
        self.ipr.flush_rules(table=self._table_name)
        self.ipr.flush_rules(table=self._table_name, family=socket.AF_INET6)
        self.ipr.flush_routes(table=self._table_name)
        self.ipr.flush_routes(table=self._table_name, family=socket.AF_INET6)

    def _apply_routing_policies(self):
        for policy in self.routing_policies:
            policy.up(self.ipr, self._table_name)

    def _apply_custom_routes(self):
        for net in self.exemption_nets:
            route = get_route_for_dst_net(net)
            if route is not None:
                self.ipr.route(
                    "add",
                    table=self._table_name,
                    family=route["family"],
                    dst=str(net),
                    oif=route.get_attr("RTA_OIF"),
                    gw=route.get_attr("RTA_GATEWAY"),
                )
                iface_name = get_iface_name_for_idx(route.get_attr("RTA_OIF"))
                add_iptables_nat_masquerade(iface_name, self.ipv6)

    def _cleanup_custom_routes(self):
        for net in self.exemption_nets:
            route = get_route_for_dst_net(net)
            if route is not None:
                iface_name = get_iface_name_for_idx(route.get_attr("RTA_OIF"))
                del_iptables_nat_masquerade(iface_name, self.ipv6)

    def _create_routing_tables(self):
        iface_idx = self.ipr.link_lookup(ifname=self.interface)
        if len(iface_idx) == 0:
            raise RuntimeError(f"Interface {self.interface} not found")
        iface_idx = iface_idx[0]
        # add default route over interface
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

        self._apply_custom_routes()

        add_iptables_nat_masquerade(self.interface, self.ipv6)

        logger.info("Created routing tables")

    def up(self):
        try:
            self._clean_up()
        except Exception:
            pass

        self._create_routing_tables()
        self._apply_routing_policies()

    def down(self):
        self._clean_up()

        del_iptables_nat_masquerade(self.interface, self.ipv6)
        self._cleanup_custom_routes()

        for policy in self.routing_policies:
            policy.down(self.ipr)

    def action(self):
        for policy in self.routing_policies:
            policy.action()

    def __enter__(self):
        self.up()
        return self

    def __exit__(self, _type, _value, _traceback):
        self.down()
        self.ipr.close()
