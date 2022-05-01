import ipaddress
import shutil
import socket
import subprocess
from typing import Any, List, Optional, Set
import os

from pyroute2 import netns

from wepwawet.ipr import IPR

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

PRIVATE_SUBNET_PREFIX = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
]


def _exec_iptables(cmd: List[str], ipv6: bool):
    iptables = shutil.which("iptables")
    if iptables is None:
        raise RuntimeError("iptables executable not found")
    subprocess.run([iptables, *cmd])
    if ipv6:
        ip6tables = shutil.which("ip6tables")
        if ip6tables is None:
            raise RuntimeError("ip6tables executable not found")
        subprocess.run([ip6tables, *cmd])


def add_iptables_nat_masquerade(iface: str, comment: str, ipv6: bool):
    _exec_iptables(
        [
            "-t",
            "nat",
            "-I",
            "POSTROUTING",
            "-o",
            iface,
            "-m",
            "comment",
            "--comment",
            comment,
            "-j",
            "MASQUERADE",
        ],
        ipv6,
    )


def del_iptables_nat_masquerade(iface: str, comment: str, ipv6: bool):
    _exec_iptables(
        [
            "-t",
            "nat",
            "-D",
            "POSTROUTING",
            "-o",
            iface,
            "-m",
            "comment",
            "--comment",
            comment,
            "-j",
            "MASQUERADE",
        ],
        ipv6,
    )


def _get_tables() -> Set[int]:
    tables: Set[int] = set()

    for rules in IPR.ipr.get_rules():
        tables.add(rules.get_attr("FRA_TABLE"))

    return tables


def is_table_in_use(table: int) -> bool:
    return table in _get_tables()


def find_free_table_name(table_start: int = 10111) -> int:
    tables = _get_tables()
    while table_start in tables:
        if table_start > 4294967295:
            raise RuntimeError("Could not found free table")

        table_start += 1

    return table_start


def find_free_netns_name(ns_name_base="wepwawet"):
    i = 0
    net_namespaces = netns.listnetns()
    while f"{ns_name_base}{i}" in net_namespaces:
        i += 1
    return f"{ns_name_base}{i}"


def _get_all_links() -> List[str]:
    links = []
    for link in IPR.ipr.get_links():
        links.append(link.get_attr("IFLA_IFNAME"))
    return links


def find_free_link_name(base_name="wepwawet") -> str:
    i = 0
    links = _get_all_links()
    while f"{base_name}{i}" in links:
        i += 1
    return f"{base_name}{i}"


def subnet_overlap_in_list(subnet, subnet_list):
    for net in subnet_list:
        if subnet.overlaps(net):
            return True
    return False


def find_unallocated_ip4_subnet(
    subnet_size: int,
) -> ipaddress.IPv4Network:
    allocated_subnets = []
    # collect subnets from routes
    for route in IPR.ipr.get_routes():
        dst = route.get_attr("RTA_DST")
        if dst is None:
            continue

        allocated_subnets.append(
            ipaddress.ip_network(f"{dst}/{route['dst_len']}", strict=False)
        )

    # get link addresses
    for addr in IPR.ipr.get_addr():
        ip = addr.get_attr("IFA_ADDRESS")
        prefix_len = addr["prefixlen"]
        allocated_subnets.append(
            ipaddress.ip_network(f"{ip}/{prefix_len}", strict=False)
        )

    for prefix in PRIVATE_SUBNET_PREFIX:
        # supernet cannot be smaller than subnet...
        if prefix.prefixlen > subnet_size:
            continue

        for net in prefix.subnets(new_prefix=subnet_size):
            if not subnet_overlap_in_list(net, allocated_subnets):
                return net

    raise RuntimeError("No free subnet found")


def family_of_ip(net: IPNetwork | IPAddress) -> int:
    if isinstance(net, ipaddress.IPv4Network) or isinstance(net, ipaddress.IPv4Address):
        return socket.AF_INET
    elif isinstance(net, ipaddress.IPv6Network) or isinstance(
        net, ipaddress.IPv6Address
    ):
        return socket.AF_INET6
    else:
        return -1


def get_iface_name_for_idx(idx: int) -> Optional[str]:
    iface = IPR.ipr.get_links(idx)
    if len(iface) > 0:
        return iface[0].get_attr("IFLA_IFNAME")
    return None


def get_route_for_dst_net(net: IPNetwork) -> Optional[Any]:
    for route in IPR.ipr.get_routes():
        dst = route.get_attr("RTA_DST")
        if dst is None:
            continue

        route_net = ipaddress.ip_network(f"{dst}/{route['dst_len']}")
        if family_of_ip(net) == route["family"] and route_net.overlaps(net):
            return route

    return None


def mkdir(path: str):
    parts = os.path.split(path)

    for part in parts:
        if not os.path.exists(part):
            os.mkdir(part)
