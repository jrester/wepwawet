# Wepwawet

Route the traffic of a process over a interface.

> Note: currently only IPv4 is working.

# Install

Install using pip:

```bash
$ pip install wepwawet
```

# Examples

Route over `wg0` interface and drop a bash shell:

```bash
$ sudo wepwawet --interface wg0 exec /bin/bash
```

> Note: when running a shell or something similar, make sure to **correctly** exit. Otherwise cleanup will not work and you will end up with zombie tables, iptable rules, etc.

Don't route subnet `192.168.0.0/24` and `192.168.1.0/24` over the vpn (e.g. for a home network) and use the DNS `1.1.1.1`:

```bash
$ sudo wepwawet --exclude 192.168.0.0/24 --exclude 192.168.1.0/24 --dns 1.1.1.1 exec "ping 192.168.0.1"
```

Only route a specific subnet over the interface, but the other traffic flows through your default interface:

```bash
$ sudo wepwawet --net 192.168.0.0/24 exec /bin/bash
```

> Note: This creates an iptable masquerade rule for most interfaces on the system. Depending on the number of interfaces, this might get a little bit messy...

# Disable automatic rule creation in your VPN

## Wireguard

Add to your wireguard interface configuration file:

```toml
[Interface]
...
Table = off
...
```
