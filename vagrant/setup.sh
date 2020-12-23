#!/bin/bash
set -eux

PEER_NR=4

for ((i=1;i<=$PEER_NR;i++));do
    ./add.sh client-$i 192.168.100.10$i
done

for ((i=1;i<=$PEER_NR;i++));do
    vagrant ssh client-$i -- sudo /vagrant/wgsd-client -device wg0 -dns 192.168.100.10:5353 -zone example.com.
done

for ((i=1;i<=$PEER_NR;i++));do
    vagrant ssh client-$i -- ping -c2 192.168.100.10
    for ((j=1;j<=$PEER_NR;j++));do
        vagrant ssh client-$i -- ping -c2 192.168.100.10$j
    done
done
