#!/bin/bash
set -eux

#
# connect clients to the registry
# setup mesh between clients
#

MYDIR="$(dirname "$(readlink -f "$0")")"

# setup each client to connect to the registry (on-boarding)
"$MYDIR"/add.sh client-1 192.168.100.101
"$MYDIR"/add.sh client-2 192.168.100.102
"$MYDIR"/add.sh client-3 192.168.100.103
"$MYDIR"/add.sh client-4 192.168.100.104

# setup mesh connections between clients
KEY1="$(vagrant ssh client-1 -- cat /etc/wireguard/publickey)"
KEY2="$(vagrant ssh client-2 -- cat /etc/wireguard/publickey)"
KEY3="$(vagrant ssh client-3 -- cat /etc/wireguard/publickey)"
KEY4="$(vagrant ssh client-4 -- cat /etc/wireguard/publickey)"
vagrant ssh client-1 -- sudo bash -s << EOF
wg set wg0 peer '$KEY2' allowed-ips 192.168.100.102/32
wg set wg0 peer '$KEY3' allowed-ips 192.168.100.103/32
wg set wg0 peer '$KEY4' allowed-ips 192.168.100.104/32
EOF
vagrant ssh client-2 -- sudo bash -s << EOF
wg set wg0 peer '$KEY1' allowed-ips 192.168.100.101/32
wg set wg0 peer '$KEY3' allowed-ips 192.168.100.103/32
wg set wg0 peer '$KEY4' allowed-ips 192.168.100.104/32
EOF
vagrant ssh client-3 -- sudo bash -s << EOF
wg set wg0 peer '$KEY1' allowed-ips 192.168.100.101/32
wg set wg0 peer '$KEY2' allowed-ips 192.168.100.102/32
wg set wg0 peer '$KEY4' allowed-ips 192.168.100.104/32
EOF
vagrant ssh client-4 -- sudo bash -s << EOF
wg set wg0 peer '$KEY1' allowed-ips 192.168.100.101/32
wg set wg0 peer '$KEY2' allowed-ips 192.168.100.102/32
wg set wg0 peer '$KEY3' allowed-ips 192.168.100.103/32
EOF
# wgsd magic
vagrant ssh client-1 -- sudo /vagrant/wgsd-client -device wg0 -dns 192.168.100.10:5353 -zone example.com.
vagrant ssh client-2 -- sudo /vagrant/wgsd-client -device wg0 -dns 192.168.100.10:5353 -zone example.com.
vagrant ssh client-3 -- sudo /vagrant/wgsd-client -device wg0 -dns 192.168.100.10:5353 -zone example.com.
# client-4 has been connected to 1/2/3 at this point

# smoke-test: ping working means both directions work, no need for all combinations
vagrant ssh client-1 -- bash -s << EOF
ping -c2 192.168.100.102
ping -c2 192.168.100.103
ping -c2 192.168.100.104
EOF
vagrant ssh client-2 -- bash -s << EOF
ping -c2 192.168.100.103
ping -c2 192.168.100.104
EOF
vagrant ssh client-3 -- ping -c2 192.168.100.104
