# Wepwawet

A simple tool for routing traffic over VPNs using policies. Following policies are currently supported:

* **user** - Route traffic based on the user ID.
* **process** - Route only traffic of a specific process.



# Install

Install and update using pip:

```bash
$ pip install wepwawet
```

# Examples

Execute a command and route their traffic over a VPN. With config file:

```bash
$ sudo wepwawet --config-file /etc/wepwawet/wepwawet.yaml exec /bin/bash
```

Use existing VPN with interface wg0:

```bash
$ sudo wepwawet --interface wg0 exec "ping 1.1.1.1"
```

Don't route subnet `192.168.0.0/24` and `192.168.1.0/24` over the vpn (e.g. for a home network):

```bash
$ sudo wepwawet --config-file /etc/wepwawet --net 192.168.0.0/24 --net 192.168.1.0/24 exec "ping 1.1.1.1"
```

# Features

- [x] uid routing
- [x] network namespaces
  - [x] per process routing
  - [ ] per container routing
- [x] Killswitch
- [x]
- [ ] VPNs
  - [x] wireguard
  - [ ] OpenVPN
- [ ] ipv6

# Config

## 1. Example Configuration

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
| `vpn` | configuration for the VPN |

## 2. Polices

Currently only the UID policy is supported.

### 2.1. Routing only traffic of specific user over VPN

```yaml
- type: uid
  uid_range: 963:963
  killswitch: true
```

| option | value |
| --- | --- |
| type | uid |
| uid_range | colon delimited uids to route over the VPN |
| killswitch | toggle whether the traffic should be dropped if the VPN interface goes down |


### 2.2. Process

```yaml
- type: process
```
