# Tunnel splitter

A callout driver implementing policy-based routing for Windows, based on process name.
Redirects TCP connections of a given process into a given network, despite of a default route.

# PoC demo:
https://youtu.be/XoELN630Ibg

# What features could be based on split tunneling:
- selectively exclude/include certain apps from VPN
- implement dual VPN w/o virtual machine (exclude server node from tunnel)
- selectively exclude/include certain connections (IP-based) from VPN
- selective kill switch: block certain apps if VPN connection drops
