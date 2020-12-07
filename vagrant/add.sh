#!/bin/sh
set -eux
VM=$1
ADDR=$2

SERVER_KEY=$(vagrant ssh registry -- cat /etc/wireguard/publickey)

vagrant ssh $VM -- sudo bash -s << EOF
wg genkey | tee /etc/wireguard/privatekey | wg pubkey | tee /etc/wireguard/publickey
# linux  config
cat > /etc/wireguard/wg0.conf << CLIENTEOF
[Interface]
PrivateKey = \$(cat /etc/wireguard/privatekey)
Address = $ADDR/24
ListenPort = 51820
[Peer]
PublicKey = $SERVER_KEY
Endpoint = 192.168.33.10:51820
AllowedIPs = 192.168.100.10/32
CLIENTEOF
chmod 600 /etc/wireguard/{privatekey,wg0.conf}
chmod 644 /etc/wireguard/publickey
chmod 711 /etc/wireguard
EOF

CLIENT_KEY=$(vagrant ssh $VM -- cat /etc/wireguard/publickey)

vagrant ssh registry -- sudo wg set wg0 peer $CLIENT_KEY allowed-ips $ADDR/32

vagrant ssh $VM -- sudo systemctl enable wg-quick@wg0
vagrant ssh $VM -- sudo systemctl restart wg-quick@wg0
vagrant ssh $VM -- ping -c2 192.168.100.10
