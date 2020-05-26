# wgsd
`wgsd` is a [CoreDNS](https://github.com/coredns/coredns) plugin that provides WireGuard peer information via DNS-SD ([RFC6763](https://tools.ietf.org/html/rfc6763)) semantics. This enables dynamic discovery of WireGuard Endpoint addressing (both IP and port) with the added of benefit of NAT-to-NAT WireGuard connectivity where [UDP hole punching](https://en.wikipedia.org/wiki/UDP_hole_punching) is supported.

See [this blog post](https://www.jordanwhited.com/posts/wireguard-endpoint-discovery-nat-traversal/) for a deep dive on the underlying techniques and development thought.

## Installation
External CoreDNS plugins can be enabled in one of two ways:

1. [Build with compile-time configuration file](https://coredns.io/2017/07/25/compile-time-enabling-or-disabling-plugins/#build-with-compile-time-configuration-file)
2. [Build with external golang source code](https://coredns.io/2017/07/25/compile-time-enabling-or-disabling-plugins/#build-with-external-golang-source-code)

For method #2 you can simply `go build` the contents of [cmd/coredns](cmd/coredns). The resulting binary is CoreDNS server with all the "internal" plugins + `wgsd`.

A basic client is available under [cmd/wgsd-client](cmd/wgsd-client).
## Configuration

```
.:53 {
  wgsd <zone> <wg device>
}
```

For example:
```
$ cat Corefile
.:53 {
  wgsd example.com. wg0
}
```

## Example Data

## TODOs
- [ ] SOA record support
- [ ] CI & release binaries