import ipaddress
import socket
from typing import List, Tuple, Optional
import os

from pyroute2 import NetNS, NSPopen
from wepwawet.utils import find_unallocated_ip4_subnet, find_free_link_name, mkdir


class RoutingPolicy:
    def __init__(
        self,
        table_name: int = 10111,
        priority: int = 100,
        killswitch: bool = True,
        ipv6: bool = False,
    ):
        self._table_name = table_name
        self._priority = priority
        self._killswitch = killswitch
        self._ipv6 = ipv6

    def up(self, _ipr):
        pass

    def action(self):
        pass

    def down(self, _ipr):
        pass


class UserPolicy(RoutingPolicy):
    """UserPolicy used for only routing traffic of a specific user over VPN"""

    def __init__(self, uid_range: Tuple[int, int], **kwargs):
        super().__init__(**kwargs)
        self._uid_range = uid_range

    def up(self, ipr):
        rule = {
            "uid_range": f"{self._uid_range[0]}:{self._uid_range[1]}",
            "table": self._table_name,
            "priority": 100,
        }
        ipr.rule("add", **rule)
        ipr.rule("add", **rule, family=socket.AF_INET6)

        if self._killswitch:
            rule["priority"] += 1
            ipr.rule("add", **rule, action="prohibit")
            ipr.rule("add", **rule, action="prohibit", family=socket.AF_INET6)

    @staticmethod
    def from_dict(config_dict: dict):
        uid_range = config_dict["uid_range"].split(":")
        return UserPolicy(
            (uid_range[0], uid_range[1]), killswitch=config_dict["killswitch"]
        )


class NetNamespacePolicy(RoutingPolicy):
    DEFAULT_NETS_INTERFACE = "wepwawet"

    def __init__(self, ns_name: str, dns: Optional[List[str]] = None, **kwargs):
        super().__init__(**kwargs)
        self._ns_name = ns_name
        self._dns = dns
        self._mask = 30
        self._veth_pair = self._get_veth_pair_name()
        self._ip4_pair = self._get_ip4_pair()

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

    def up(self, ipr, *args, **kwargs):
        # create network namespace
        self._ns = NetNS(self._ns_name)
        # create a veth pair to connect the namespace with the outside
        ipr.link(
            "add",
            ifname=self._veth_pair[0],
            kind="veth",
            peer={"ifname": self._veth_pair[1], "net_ns_fd": self._ns_name},
        )
        idx0 = ipr.link_lookup(ifname=self._veth_pair[0])[0]
        idx1 = self._ns.link_lookup(ifname=self._veth_pair[1])[0]

        # add the ip addresses to the veth pair
        ipr.addr("add", index=idx0, address=self._ip4_pair[0].exploded, mask=self._mask)
        self._ns.addr(
            "add", index=idx1, address=self._ip4_pair[1].exploded, mask=self._mask
        )

        # bring the veth pair up
        ipr.link("set", index=idx0, state="up")
        self._ns.link("set", index=idx1, state="up")

        # route traffic to the veth peer in the default namespace
        self._ns.route("add", dst="default", gateway=self._ip4_pair[0].exploded)

        rule = {
            "iifname": self._veth_pair[0],
            "table": self._table_name,
            "priority": self._priority,
        }

        ipr.rule("add", **rule)
        if self._ipv6:
            ipr.rule("add", **rule, family=socket.AF_INET6)

        if self._killswitch:
            rule["priority"] += 1
            ipr.rule("add", **rule, action="prohibit")
            if self._ipv6:
                ipr.rule("add", **rule, action="prohibit", family=socket.AF_INET6)

        if self._dns:
            self._create_resolv_conf()

    def down(self, ipr, *args, **kwargs):
        ipr.link("del", ifname=self._veth_pair[0])
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
