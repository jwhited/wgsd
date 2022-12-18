# wgsd
`wgsd` is a [CoreDNS](https://github.com/coredns/coredns) plugin that serves WireGuard® peer information via DNS-SD ([RFC6763](https://tools.ietf.org/html/rfc6763)) semantics. This enables use cases such as:
* Building a mesh of WireGuard peers from a central registry
* Dynamic discovery of WireGuard Endpoint addressing (both IP address and port number)
* NAT-to-NAT WireGuard connectivity where [UDP hole punching](https://en.wikipedia.org/wiki/UDP_hole_punching) is supported.

See [this blog post](https://www.jordanwhited.com/posts/wireguard-endpoint-discovery-nat-traversal/) for a deep dive on the underlying techniques and development thought.

## Installation
Binary releases are available [here](https://github.com/jwhited/wgsd/releases).

Each release contains 2 binaries:
* `coredns` - CoreDNS server with all the "internal" plugins + `wgsd`
* `wgsd-client` - A sample client

## Building from source
External CoreDNS plugins can be enabled in one of two ways:

1. [Build with compile-time configuration file](https://coredns.io/2017/07/25/compile-time-enabling-or-disabling-plugins/#build-with-compile-time-configuration-file)
2. [Build with external golang source code](https://coredns.io/2017/07/25/compile-time-enabling-or-disabling-plugins/#build-with-external-golang-source-code)

For method #2 you can simply `go build` the contents of [cmd/coredns](cmd/coredns). The resulting binary is CoreDNS server with all the "internal" plugins + `wgsd`.

```
% go build
% ./coredns -plugins | grep wgsd
  dns.wgsd
```

A basic client is available under [cmd/wgsd-client](cmd/wgsd-client).

## Configuration Syntax

```
wgsd ZONE DEVICE
```

* `ZONE` is the zone name wgsd should be authoritative for, e.g. example.com.
* `DEVICE` is the name of the WireGuard interface, e.g. wg0

```
wgsd ZONE DEVICE {
    self [ ENDPOINT ] [ ALLOWED-IPS ... ]
}
```

* Supplying the `self` option enables serving data about the local WireGuard device in addition to its peers. The optional `ENDPOINT` argument enables setting a custom endpoint in ip:port form. If `ENDPOINT` is omitted wgsd will default to the local IP address for the DNS query and `ListenPort` of the WireGuard device. This can be useful if your host is behind NAT. The optional, variadic `ALLOWED-IPS` argument sets allowed-ips to be served for the local WireGuard device.

## Querying

Following RFC6763 this plugin provides a listing of peers via PTR records at the namespace `_wireguard._udp.<zone>`. The target for the PTR records is of the format  `<base32PubKey>._wireguard._udp.<zone>`. This same format is used for the accompanying SRV, A/AAAA, and TXT records. When querying the SRV record for a peer, the target A/AAAA & TXT records will be included in the "additional" section of the response. TXT records include Base64 public key and allowed IPs. Public keys are represented in Base32 rather than Base64 in record names as they are treated as case-insensitive by the DNS.

## Example

This configuration:
```
$ cat Corefile
.:5353 {
  wgsd example.com. wg0 {
    self 192.0.2.1:51820 10.0.0.254/32
  }
}
```

With the following WireGuard peers:
```
$ sudo wg show
interface: wg0
  public key: JeZlz14G8tg1Bqh6apteFCwVhNhpexJ19FDPfuxQtUY=
  private key: (hidden)
  listening port: 51820

peer: xScVkH3fUGUv4RrJFfmcqm8rs3SEHr41km6+yffAHw4=
  endpoint: 203.0.113.1:7777
  allowed ips: 10.0.0.1/32
  latest handshake: 14 hours, 24 minutes, 40 seconds ago
  transfer: 840.64 KiB received, 85.54 KiB sent

peer: syKB97XhGnvC+kynh2KqQJPXoOoOpx/HmpMRTc+r4js=
  endpoint: 198.51.100.1:8888
  allowed ips: 10.0.0.2/32
  latest handshake: 4 days, 15 hours, 8 minutes, 12 seconds ago
  transfer: 1.38 MiB received, 139.42 KiB sent
```

Will respond with:
```
$ dig @127.0.0.1 -p 5353 _wireguard._udp.example.com. PTR +noall +answer +additional
_wireguard._udp.example.com. 0	IN	PTR	yutrled535igkl7bdlerl6m4vjxsxm3uqqpl4nmsn27mt56ad4ha====._wireguard._udp.example.com.
_wireguard._udp.example.com. 0	IN	PTR	wmrid55v4enhxqx2jstyoyvkicj5pihkb2tr7r42smiu3t5l4i5q====._wireguard._udp.example.com.
_wireguard._udp.example.com. 0	IN	PTR	extglt26a3znqnigvb5gvg26cqwblbgynf5re5pukdhx53cqwvda====._wireguard._udp.example.com.
$
$ dig @127.0.0.1 -p 5353 yutrled535igkl7bdlerl6m4vjxsxm3uqqpl4nmsn27mt56ad4ha====._wireguard._udp.example.com. SRV +noall +answer +additional
yutrled535igkl7bdlerl6m4vjxsxm3uqqpl4nmsn27mt56ad4ha====._wireguard._udp.example.com. 0	IN SRV 0 0 7777 yutrled535igkl7bdlerl6m4vjxsxm3uqqpl4nmsn27mt56ad4ha====._wireguard._udp.example.com.
yutrled535igkl7bdlerl6m4vjxsxm3uqqpl4nmsn27mt56ad4ha====._wireguard._udp.example.com. 0	IN A 203.0.113.1
yutrled535igkl7bdlerl6m4vjxsxm3uqqpl4nmsn27mt56ad4ha====._wireguard._udp.example.com. 0	IN TXT "txtvers=1" "pub=xScVkH3fUGUv4RrJFfmcqm8rs3SEHr41km6+yffAHw4=" "allowed=10.0.0.1/32"
$
$ dig @127.0.0.1 -p 5353 wmrid55v4enhxqx2jstyoyvkicj5pihkb2tr7r42smiu3t5l4i5q====._wireguard._udp.example.com. SRV +noall +answer +additional
wmrid55v4enhxqx2jstyoyvkicj5pihkb2tr7r42smiu3t5l4i5q====._wireguard._udp.example.com. 0	IN SRV 0 0 8888 wmrid55v4enhxqx2jstyoyvkicj5pihkb2tr7r42smiu3t5l4i5q====._wireguard._udp.example.com.
wmrid55v4enhxqx2jstyoyvkicj5pihkb2tr7r42smiu3t5l4i5q====._wireguard._udp.example.com. 0	IN A 198.51.100.1
wmrid55v4enhxqx2jstyoyvkicj5pihkb2tr7r42smiu3t5l4i5q====._wireguard._udp.example.com. 0	IN TXT "txtvers=1" "pub=syKB97XhGnvC+kynh2KqQJPXoOoOpx/HmpMRTc+r4js=" "allowed=10.0.0.2/32"
$
$ dig @127.0.0.1 -p 5353 extglt26a3znqnigvb5gvg26cqwblbgynf5re5pukdhx53cqwvda====._wireguard._udp.example.com. SRV +noall +answer +additional
extglt26a3znqnigvb5gvg26cqwblbgynf5re5pukdhx53cqwvda====._wireguard._udp.example.com. 0	IN SRV 0 0 51820 extglt26a3znqnigvb5gvg26cqwblbgynf5re5pukdhx53cqwvda====._wireguard._udp.example.com.
extglt26a3znqnigvb5gvg26cqwblbgynf5re5pukdhx53cqwvda====._wireguard._udp.example.com. 0	IN A 192.0.2.1
extglt26a3znqnigvb5gvg26cqwblbgynf5re5pukdhx53cqwvda====._wireguard._udp.example.com. 0	IN TXT "txtvers=1" "pub=JeZlz14G8tg1Bqh6apteFCwVhNhpexJ19FDPfuxQtUY=" "allowed=10.0.0.254/32"
```

Converting public keys to Base64 with coreutils:
```
$ echo yutrled535igkl7bdlerl6m4vjxsxm3uqqpl4nmsn27mt56ad4ha==== | tr '[:lower:]' '[:upper:]' | base32 -d | base64
xScVkH3fUGUv4RrJFfmcqm8rs3SEHr41km6+yffAHw4=
$ echo wmrid55v4enhxqx2jstyoyvkicj5pihkb2tr7r42smiu3t5l4i5q==== | tr '[:lower:]' '[:upper:]' | base32 -d | base64
syKB97XhGnvC+kynh2KqQJPXoOoOpx/HmpMRTc+r4js=
$ echo extglt26a3znqnigvb5gvg26cqwblbgynf5re5pukdhx53cqwvda==== | tr '[:lower:]' '[:upper:]' | base32 -d | base64
JeZlz14G8tg1Bqh6apteFCwVhNhpexJ19FDPfuxQtUY=
```

## TODOs
- [x] unit tests
- [ ] SOA record support
- [x] CI & release binaries

## Legal
WireGuard is a registered trademark of Jason A. Donenfeld.