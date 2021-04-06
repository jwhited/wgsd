package wgsd

import (
	"fmt"
	"net"
	"strconv"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
	"golang.zx2c4.com/wireguard/wgctrl"
)

func init() {
	plugin.Register(pluginName, setup)
}

func parse(c *caddy.Controller) (Zones, error) {
	z := make(map[string]*Zone)
	names := []string{}

	for c.Next() {
		// wgsd zone device
		args := c.RemainingArgs()
		if len(args) != 2 {
			return Zones{}, fmt.Errorf("expected 2 args, got %d", len(args))
		}
		zone := &Zone{
			name:   dns.Fqdn(args[0]),
			device: args[1],
		}
		names = append(names, zone.name)
		_, ok := z[zone.name]
		if ok {
			return Zones{}, fmt.Errorf("duplicate zone name %s",
				zone.name)
		}
		z[zone.name] = zone

		for c.NextBlock() {
			zone.onlySubnets = false
			switch c.Val() {
			case "only-propagate-subnets":
				zone.onlySubnets = true
			case "self":
				// self [endpoint] [allowed-ips ... ]
				zone.serveSelf = true
				args = c.RemainingArgs()
				if len(args) < 1 {
					break
				}

				// assume first arg is endpoint
				host, portS, err := net.SplitHostPort(args[0])
				if err == nil {
					port, err := strconv.Atoi(portS)
					if err != nil {
						return Zones{}, fmt.Errorf("error converting self endpoint port: %v", err)
					}
					ip := net.ParseIP(host)
					if ip == nil {
						return Zones{}, fmt.Errorf("invalid self endpoint IP address: %s", host)
					}
					zone.selfEndpoint = &net.UDPAddr{
						IP:   ip,
						Port: port,
					}
					args = args[1:]
				}

				if len(args) > 0 {
					zone.selfAllowedIPs = make([]net.IPNet, 0)
				}
				for _, allowedIPString := range args {
					_, prefix, err := net.ParseCIDR(allowedIPString)
					if err != nil {
						return Zones{}, fmt.Errorf("invalid self allowed-ip '%s' err: %v", allowedIPString, err)
					}
					zone.selfAllowedIPs = append(zone.selfAllowedIPs, *prefix)
				}
			default:
				return Zones{}, c.ArgErr()
			}
		}
	}

	return Zones{Z: z, Names: names}, nil
}

func setup(c *caddy.Controller) error {
	zones, err := parse(c)
	if err != nil {
		return plugin.Error(pluginName, err)
	}
	client, err := wgctrl.New()
	if err != nil {
		return plugin.Error(pluginName,
			fmt.Errorf("error constructing wgctrl client: %v",
				err))
	}
	c.OnFinalShutdown(client.Close)

	// Add the Plugin to CoreDNS, so Servers can use it in their plugin chain.
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return &WGSD{
			Next:   next,
			Zones:  zones,
			client: client,
		}
	})
	return nil
}
