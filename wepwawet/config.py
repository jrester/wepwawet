from enum import Enum
import ipaddress
from typing import List

import yaml
from schema import Optional, Schema
from wepwawet.policies import UserPolicy


class VPNType(Enum):
    WIREGUARD = "wireguard"
    OPENVPN = "openvpn"


UID_POLICY_SCHEMA = Schema({"type": "uid", "uid_range": str, "killswitch": bool})

WG_SCHEMA = Schema(
    {
        "type": "wireguard",
        "interface": {"address": list, "private_key": str},
        "peer": {
            "public_key": str,
            Optional("preshared_key"): str,
            "allowed_ips": list,
            "endpoint": str,
            "keepalive": int,
        },
    }
)

SCHEMA = Schema(
    {
        "table_name": int,
        "policies": list,
        "vpn": dict,
        "interface": str,
        Optional("ipv6", default=True): bool,
        Optional("nets", default=[]): list, 
    }
)


class Config:
    def __init__(self, table_name, policies, vpn, interface, ipv6, nets: List[str]):
        self.table_name = table_name
        self.policies = policies
        self.interface = interface
        self.ipv6 = ipv6
        self.vpn = vpn
        self.nets = [ipaddress.ip_network(net) for net in nets]

    @staticmethod
    def from_dict(config_dict: dict) -> "Config":
        validated = SCHEMA.validate(config_dict)
        if validated["vpn"]["type"] == VPNType.WIREGUARD.value:
            vpn_config = WG_SCHEMA.validate(validated["vpn"])
        else:
            raise ValueError(f"Unsupported VPN type: {validated['vpn']['type']}")

        validated["vpn"] = vpn_config
        policies = []
        for policy in validated["policies"]:
            if policy["type"] == "uid":
                policies.append(
                    UserPolicy.from_dict(UID_POLICY_SCHEMA.validate(policy))
                )
            else:
                raise ValueError(f"Unsupported policy type: {policy['type']}")

        validated["policies"] = policies

        return Config(**validated)

    @staticmethod
    def from_file(path: str):
        with open(path, "r") as f:
            return Config.from_dict(yaml.load(f, Loader=yaml.FullLoader))
