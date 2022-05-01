import ipaddress
import socket
from typing import List, Tuple, Optional
import os
import logging

from pyroute2 import NetNS, NSPopen
from wepwawet.ipr import IPR
from wepwawet.utils import (
    IPNetwork,
    add_iptables_nat_masquerade,
    del_iptables_nat_masquerade,
    family_of_ip,
    find_unallocated_ip4_subnet,
    find_free_link_name,
    get_iface_name_for_idx,
    get_route_for_dst_net,
    mkdir,
)

logger = logging.getLogger("wepwawet")


class RoutingPolicy:
    def __init__(
        self,
        interface: str,
        identifier: str,
        table: int = 10111,
        priority: int = 100,
        killswitch: bool = True,
        ipv6: bool = False,
        nets: List[IPNetwork] = [],
        exclude_nets: List[IPNetwork] = [],
    ):
        self._interface = interface
        self._identifier = identifier
        self._table = table
        self._priority = priority
        self._killswitch = killswitch
        self._ipv6 = ipv6
        self._exclude_nets = exclude_nets
        self._nets = nets
        self._no_default_route = len(self._nets) > 0

    def _add_exemption_routes(self, nets: List[IPNetwork]):
        for net in nets:
            logging.info("add exemption route for %s", net)
            route = get_route_for_dst_net(net)
            if route is not None:
                IPR.ipr.route(
                    "add",
                    table=self._table,
                    family=route["family"],
                    dst=str(net),
                    oif=route.get_attr("RTA_OIF"),
                    gw=route.get_attr("RTA_GATEWAY"),
                )
                iface_name = get_iface_name_for_idx(route.get_attr("RTA_OIF"))
                if iface_name is None:
                    raise RuntimeError(f"Could not find interface for {route}")
                add_iptables_nat_masquerade(iface_name, self._identifier, self._ipv6)

    def _cleanup_exemption_routes(self, nets: List[IPNetwork]):
        for net in nets:
            route = get_route_for_dst_net(net)
            if route is not None:
                iface_name = get_iface_name_for_idx(route.get_attr("RTA_OIF"))
                if iface_name is None:
                    raise RuntimeError(f"Could not find interface for {route}")
                del_iptables_nat_masquerade(iface_name, self._identifier, self._ipv6)

    def _flush_tables(self):
        logger.info("flush tables")
        IPR.ipr.flush_rules(table=self._table, family=socket.AF_INET)
        IPR.ipr.flush_routes(table=self._table, family=socket.AF_INET)
        # also flush ipv6 tables, even though ipv6 might not be enabled
        # because we created the prohibit rule for ipv6
        IPR.ipr.flush_rules(table=self._table, family=socket.AF_INET6)
        IPR.ipr.flush_routes(table=self._table, family=socket.AF_INET6)

    def _should_masquerade_link(self, iface_name: str) -> bool:
        return (
            iface_name != self._interface
            and iface_name != "lo"
            and iface_name != self._identifier
        )

    def _create_nat_masquerade_for_all_links(self):
        for link in IPR.ipr.get_links():
            iface_name = link.get_attr("IFLA_IFNAME")
            if self._should_masquerade_link(iface_name):
                add_iptables_nat_masquerade(iface_name, self._identifier, self._ipv6)

    def _delete_nat_masquerade_for_all_links(self):
        for link in IPR.ipr.get_links():
            iface_name = link.get_attr("IFLA_IFNAME")
            if self._should_masquerade_link(iface_name):
                del_iptables_nat_masquerade(iface_name, self._identifier, self._ipv6)

    def _create_routing_tables(self):
        logger.info("creating routing tables")
        iface_idx = IPR.ipr.link_lookup(ifname=self._interface)
        if len(iface_idx) == 0:
            raise RuntimeError(f"Interface {self._interface} not found")
        iface_idx = iface_idx[0]
        if self._no_default_route:
            # route the specified networks over the interface
            for net in self._nets:
                IPR.ipr.route(
                    "add",
                    table=self._table,
                    dst=net.exploded,
                    oif=iface_idx,
                    metrics={"attrs": [["RTA_PRIORITY", self._priority]]},
                    family=family_of_ip(net),
                )
                self._create_nat_masquerade_for_all_links()
        else:
            # add default route over interface
            IPR.ipr.route(
                "add",
                table=self._table,
                dst="default",
                oif=iface_idx,
                metrics={"attrs": [["RTAX_PRIORITY", 0]]},
            )
            if self._ipv6:
                IPR.ipr.route(
                    "add",
                    table=self._table,
                    dst="default",
                    oif=iface_idx,
                    metrics={"attrs": [["RTAX_PRIORITY", 100]]},
                    family=socket.AF_INET6,
                )
            else:
                # block all ipv6 traffic
                IPR.ipr.route("add", table=self._table, dst="::0/0", type="prohibit")

    def up(self):
        self._add_exemption_routes(self._exclude_nets)
        self._create_routing_tables()
        add_iptables_nat_masquerade(self._interface, self._identifier, self._ipv6)

    def action(self):
        pass

    def down(self):
        self._cleanup_exemption_routes(self._exclude_nets)
        self._flush_tables()
        if self._no_default_route:
            self._delete_nat_masquerade_for_all_links()
        del_iptables_nat_masquerade(self._interface, self._identifier, self._ipv6)

    def __enter__(self):
        self.up()
        return self

    def __exit__(self, _type, _value, _traceback):
        self.down()


class UserPolicy(RoutingPolicy):
    """UserPolicy used for only routing traffic of a specific user over VPN"""

    def __init__(self, uid_range: Tuple[int, int], **kwargs):
        super().__init__(**kwargs)
        self._uid_range = uid_range

    def up(self):
        rule = {
            "uid_range": f"{self._uid_range[0]}:{self._uid_range[1]}",
            "table": self._table,
            "priority": 100,
        }
        IPR.ipr.rule("add", **rule)
        IPR.ipr.rule("add", **rule, family=socket.AF_INET6)

        if self._killswitch:
            rule["priority"] += 1
            IPR.ipr.rule("add", **rule, action="prohibit")
            IPR.ipr.rule("add", **rule, action="prohibit", family=socket.AF_INET6)

    @staticmethod
    def from_dict(config_dict: dict):
        uid_range = config_dict["uid_range"].split(":")
        return UserPolicy(
            (uid_range[0], uid_range[1]), killswitch=config_dict["killswitch"]
        )


class NetNamespacePolicy(RoutingPolicy):
    DEFAULT_NETS_INTERFACE = "wepwawet"

    def __init__(self, ns_name: str, dns: Optional[List[str]] = None, **kwargs):
        self._ns_name = ns_name
        self._dns = dns
        self._mask = 30
        self._veth_pair = self._get_veth_pair_name()
        self._ip4_pair = self._get_ip4_pair()
        super().__init__(identifier=self._veth_pair[0], **kwargs)

    def _get_ip4_pair(self) -> Tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]:
        subnet = find_unallocated_ip4_subnet(subnet_size=30)
        return tuple(subnet.hosts())[:2]  # type: ignore

    def _get_veth_pair_name(self):
        return (find_free_link_name(), self.DEFAULT_NETS_INTERFACE)

    def _create_resolv_conf(self):
        mkdir(f"/etc/netns/{self._ns_name}")
        with open(f"/etc/netns/{self._ns_name}/resolv.conf", "w") as f:
            for dns in self._dns:
                f.write(f"nameserver {dns}\n")

    def _remove_resolv_conf(self):
        os.remove(f"/etc/netns/{self._ns_name}/resolv.conf")
        os.rmdir(f"/etc/netns/{self._ns_name}")

    def up(self, *args, **kwargs):
        super().up(*args, **kwargs)
        # create network namespace
        self._ns = NetNS(self._ns_name)
        # create a veth pair to connect the namespace with the outside
        IPR.ipr.link(
            "add",
            ifname=self._veth_pair[0],
            kind="veth",
            peer={"ifname": self._veth_pair[1], "net_ns_fd": self._ns_name},
        )
        idx0 = IPR.ipr.link_lookup(ifname=self._veth_pair[0])[0]
        idx1 = self._ns.link_lookup(ifname=self._veth_pair[1])[0]

        # add the ip addresses to the veth pair
        IPR.ipr.addr(
            "add", index=idx0, address=self._ip4_pair[0].exploded, mask=self._mask
        )
        self._ns.addr(
            "add", index=idx1, address=self._ip4_pair[1].exploded, mask=self._mask
        )

        # bring the veth pair up
        IPR.ipr.link("set", index=idx0, state="up")
        self._ns.link("set", index=idx1, state="up")

        # route traffic to the veth peer in the default namespace
        self._ns.route("add", dst="default", gateway=self._ip4_pair[0].exploded)

        rule = {
            "iifname": self._veth_pair[0],
            "table": self._table,
            "priority": self._priority,
        }

        IPR.ipr.rule("add", **rule)
        if self._ipv6:
            IPR.ipr.rule("add", **rule, family=socket.AF_INET6)

        if self._killswitch:
            rule["priority"] += 1
            IPR.ipr.rule("add", **rule, action="prohibit")
            if self._ipv6:
                IPR.ipr.rule("add", **rule, action="prohibit", family=socket.AF_INET6)

        if self._dns:
            self._create_resolv_conf()

    def down(self, *args, **kwargs):
        super().down(*args, **kwargs)
        IPR.ipr.link("del", ifname=self._veth_pair[0])
        self._ns.close()
        self._ns.remove()
        if self._dns:
            self._remove_resolv_conf()


class ProcessPolicy(NetNamespacePolicy):
    def __init__(self, cmd: List[str], **kwargs):
        super().__init__(**kwargs)
        self._cmd = cmd

    def action(self):
        nsp = NSPopen(self._ns_name, self._cmd)
        nsp.communicate()
        nsp.wait()
        nsp.release()

    @staticmethod
    def from_dict(config_dict: dict):
        return ProcessPolicy(config_dict["ipv6"])
