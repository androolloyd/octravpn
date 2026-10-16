#!/bin/sh
set -eu
# Never create this alias in an externally connected namespace. Tests repeat
# the interface/default-route checks before opening either VPN service.
[ -f /.dockerenv ] || { echo 'Docker isolation required' >&2; exit 1; }
[ "$(ls /sys/class/net)" = lo ] || { echo '--network none required' >&2; exit 1; }
[ -z "$(ip -4 route show default)" ] || { echo 'default route forbidden' >&2; exit 1; }
ip link set lo up
ip address add 93.184.216.34/32 dev lo
export OCTRAVPN_ISOLATED_TEST=1
/usr/local/bin/vpn-transport-tests migration::files::tests --nocapture --test-threads=1
/usr/local/bin/vpn-transport-tests wireguard::integration_tests::real_client_handshake --nocapture --test-threads=1
exec /usr/local/bin/vpn-transport-tests wireguard::integration_tests::isolated_ --ignored --nocapture --test-threads=1
