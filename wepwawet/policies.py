import socket
from tkinter import W
from typing import Tuple, List
from pyroute2 import NetNS, NSPopen

class RoutingPolicy:
    def __init__(self, table_name: int = 10111, priority: int = 100, killswitch: bool = True, ipv6: bool = False):
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
        return UserPolicy((uid_range[0], uid_range[1]), killswitch=config_dict["killswitch"])

class NetNamespacePolicy(RoutingPolicy):
    def __init__(self, ns_name: str, **kwargs):
        super().__init__(**kwargs)
        self._ns_name = ns_name
        self._veth_pair = self._get_veth_pair_name()
        self._ip4_pair = self._get_ip4_pair()
        self._mask = 30

    def _get_ip4_pair(self):
        return ("10.0.0.1", "10.0.0.2")

    def _get_veth_pair_name(self):
        return ("veth0", "veth1")

    def up(self, ipr, *args, **kwargs):
        # create network namespace
        self._ns = NetNS(self._ns_name)
        # create a veth pair to connect the namespace with the outside
        ipr.link('add', ifname=self._veth_pair[0], kind='veth', peer={
            "ifname": self._veth_pair[1],
            "net_ns_fd": self._ns_name
        })
        idx0 = ipr.link_lookup(ifname=self._veth_pair[0])[0] 
        idx1 = self._ns.link_lookup(ifname=self._veth_pair[1])[0]
        
        # add the ip addresses to the veth pair
        ipr.addr('add', index=idx0, address=self._ip4_pair[0], mask=self._mask)
        self._ns.addr('add', index=idx1, address=self._ip4_pair[1], mask=self._mask)

        # bring the veth pair up
        ipr.link('set', index=idx0, state='up')
        self._ns.link('set', index=idx1, state='up')

        # route traffic to the veth peer in the default namespace
        self._ns.route('add', dst='default', gateway=self._ip4_pair[0])

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


    def down(self, ipr, *args, **kwargs):
        ipr.link('del', ifname=self._veth_pair[0])
        self._ns.close()
        self._ns.remove()

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