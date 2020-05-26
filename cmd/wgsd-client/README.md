# wgsd-client
`wgsd-client` is responsible for keeping peer endpoint configuration up to date. It retrieves the list of configured peers, queries `wgsd` for matching public keys, and then sets the endpoint value for each peer if needed. This client is intended to be run periodically via cron or similar scheduling mechanism. It checks all peers once in a serialized fashion and then exits.

```
% ./wgsd-client --help
Usage of ./wgsd-client:
  -device string
    	name of Wireguard device to manage
  -dns string
    	ip:port of DNS server
  -zone string
    	dns zone name
```