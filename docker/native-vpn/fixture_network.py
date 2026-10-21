"""Per-invocation private underlay addresses for independent kernel fixtures."""
import ipaddress
import os


def addresses(value=None):
    subnet = ipaddress.IPv4Network(value or os.environ.get('OCTRA_FIXTURE_SUBNET', '172.31.237.0/24'))
    assert subnet.prefixlen == 24 and any(subnet.subnet_of(ipaddress.IPv4Network(block))
        for block in ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'])
    return {'subnet': str(subnet), **{role: str(subnet[offset]) for role, offset in [('A', 2), ('B', 4), ('C', 3)]}}
