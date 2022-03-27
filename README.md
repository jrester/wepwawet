# Wepwawet

A simple tool for routing traffic over VPNs using policies.

# Install

Install and update using pip:

```bash
$ pip install wepwawet
```
# Running

```bash
$ sudo wepwawet --config-file /etc/wepwawet
```

# Config

## Example Configuration

```yaml
table_name: 10111
policies:
  - type: uid
    uid_range: 963:963
    killswitch: true
  - type: uid
    uid_range: 972:972
    killswitch: false
interface: wg0
ipv6: false
vpn:
  type: wireguard
  interface:
    address:
      - fd9f:1234::4/128
      - 10.6.6.45/32
    private_key: abc
  peer:
    public_key: def
    # omit preshared_key if you don't have one
    preshared_key: xyz
    allowed_ips:
      - 0.0.0.0/0
      - ::0/0
    endpoint: example.com:51820
    keepalive: 16
```

| option | value |
| --- | --- |
| `table_name` | A unique `int` that is used as an identifier for the routing tables. |
| `policies` | list of policies to apply for the VPN |
| `interface` | name of the interface that is going to be created for the VPN |
| `ipv6` | whether IPv6 should be enabled |
| `vpn` | configuration for the VPN |

## Polices

Currently only the UID policy is supported.

### Routing only traffic of specific user over VPN

```yaml
---
- type: uid
  uid_range: 963:963
  killswitch: true
---
```

| option | value |
| --- | --- |
| type | uid |
| uid_range | colon delimited uids to route over the VPN |
| killswitch | toggle whether the traffic should be dropped if the VPN interface goes down |
