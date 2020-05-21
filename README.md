# wgsd
`wgsd` is a CoreDNS plugin that provides Wireguard peer information via DNS-SD semantics. See [this blog post](https://www.jordanwhited.com/posts/wireguard-endpoint-discovery-nat-traversal/) for the background and reasoning behind it.

In order to use this plugin with CoreDNS first you need to [enable it](https://coredns.io/2017/07/25/compile-time-enabling-or-disabling-plugins/). Once it's enabled it can be configured like so:

```
.:53 {
  wgsd <zone> <wg device>
}
```

For example:
```
$ cat Corefile
.:53 {
  wgsd jordanwhited.net. utun4
}
```