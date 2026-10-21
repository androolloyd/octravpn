"""Unprivileged, bound-device negatives in the isolated client kernel only."""
import errno
import json
import os
import pathlib
import socket


def main():
    assert pathlib.Path('/.dockerenv').is_file()
    os.setgroups([]); os.setgid(1000); os.setuid(1000)
    capabilities = next(line.split()[1] for line in pathlib.Path('/proc/self/status').read_text().splitlines()
                        if line.startswith('CapEff:'))
    assert int(capabilities, 16) == 0
    results = []
    for protocol, peer in [('tcp', ('93.184.216.21', 20889)),
                           ('udp', ('93.184.216.21', 19884)),
                           ('udp', ('93.184.216.34', 53))]:
        kind = socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM
        with socket.socket(socket.AF_INET, kind) as channel:
            channel.settimeout(2)
            channel.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'eth0\0')
            try:
                channel.connect(peer)
                if protocol == 'udp':
                    channel.send(b'isolated physical bypass negative')
                    channel.recv(1)
                raise AssertionError('physical bypass succeeded')
            except OSError as error:
                # A timeout could be a disconnected target, not enforcement.
                assert error.errno in [errno.EPERM, errno.EACCES, errno.ECONNREFUSED, errno.ENETUNREACH], error
                results.append({'protocol': protocol, 'peer': list(peer), 'errno': error.errno})
    print(json.dumps({'uid': os.getuid(), 'effective_capabilities': capabilities, 'refused': results}))


if __name__ == '__main__': main()
