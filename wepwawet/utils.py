import ipaddress
import subprocess
import shutil
from typing import List, Optional
from pyroute2 import netns, IPRoute
import socket

def _exec_iptables(cmd: List[str], ipv6: bool):
    iptables = shutil.which("iptables")
    p: subprocess.CompletedProcess = subprocess.run([iptables, *cmd])
    p.check_returncode()
    if ipv6:
        ip6tables = shutil.which("ip6tables")
        p: subprocess.CompletedProcess = subprocess.run([ip6tables, *cmd])
        p.check_returncode()

def add_iptables_nat_masquerade(iface: str, ipv6: bool):
    _exec_iptables(['-t', 'nat', '-I', 'POSTROUTING', '-o', iface , '-j', 'MASQUERADE'], ipv6)

def del_iptables_nat_masquerade(iface: str, ipv6: bool):
    _exec_iptables(['-t', 'nat', '-D', 'POSTROUTING', '-o', iface , '-j', 'MASQUERADE'], ipv6)

def get_free_netns_name(ns_name_base = "wepwawet"):
    i = 0
    net_namespaces = netns.listnetns() 
    while f"{ns_name_base}{i}" in net_namespaces:
        i += 1
    return f"{ns_name_base}{i}"

def _get_all_links():
    links = []
    with IPRoute() as ipr:
       for link in ipr.get_links():
           links.append(link.get_attr("IFLA_IFNAME")) 
    return links

def get_free_link_name(base_name = "wepwawet"):
    i = 0
    links = _get_all_links() 
    while f"{base_name}{i}" in links:
        i += 1
    return f"{base_name}{i}"

def family_of_ip(net: ipaddress.IPv4Network | ipaddress.IPv6Network | ipaddress.IPv4Address | ipaddress.IPv6Address) -> int:
    if isinstance(net, ipaddress.IPv4Network) or isinstance(net, ipaddress.IPv4Address):
        return socket.AF_INET
    elif isinstance(net, ipaddress.IPv6Network) or isinstance(net, ipaddress.IPv6Address):
        return socket.AF_INET6
    else:
        return -1
    

def get_iface_name_for_idx(idx: int) -> Optional[str]:
    with IPRoute() as ipr:
        iface = ipr.get_links(idx)
        if len(iface) > 0:
            return iface[0].get_attr("IFLA_IFNAME")
        return None
    
def get_route_for_dst_net(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> Optional[dict]:
    with IPRoute() as ipr:
        for route in ipr.get_routes():
            dst = route.get_attr("RTA_DST")
            if dst is None:
                continue

            route_net = ipaddress.ip_network(f"{dst}/{route['dst_len']}")
            if family_of_ip(net) == route['family'] and (route_net.supernet_of(net) or route_net.subnet_of(net)):
               return route 

    return None
            