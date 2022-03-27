import socket
from typing import Tuple


class RoutingPolicy:
    def __init__(self):
        pass

    def up(self, _ipr, _table_name, **kwargs):
        pass

    def down(self, _ipr, _table_name):
        pass


class UserPolicy(RoutingPolicy):
    """UserPolicy used for only routing traffic of a specific user over VPN"""

    def __init__(self, uid_range: Tuple[int, int], killswitch: bool):
        self.uid_range = uid_range
        self.killswitch = killswitch

    def up(self, ipr, table_name, **kwargs):
        rule = {
            "uid_range": f"{self.uid_range[0]}:{self.uid_range[1]}",
            "table": table_name,
            "priority": 100,
        }
        ipr.rule("add", **rule)
        ipr.rule("add", **rule, family=socket.AF_INET6)

        if self.killswitch:
            rule["priority"] += 1
            ipr.rule("add", **rule, action="prohibit")
            ipr.rule("add", **rule, action="prohibit", family=socket.AF_INET6)

    @staticmethod
    def from_dict(config_dict: dict):
        uid_range = config_dict["uid_range"].split(":")
        return UserPolicy((uid_range[0], uid_range[1]), config_dict["killswitch"])
