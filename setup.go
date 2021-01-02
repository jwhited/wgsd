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

const (
	optionSelfAllowedIPs = "self-allowed-ips"
	optionSelfEndpoint   = "self-endpoint"
)

func parse(c *caddy.Controller) (*WGSD, error) {
	p := &WGSD{}
	for c.Next() {
		args := c.RemainingArgs()
		if len(args) != 2 {
			return nil, fmt.Errorf("expected 2 args, got %d", len(args))
		}
		p.zone = dns.Fqdn(args[0])
		p.device = args[1]

		for c.NextBlock() {
			switch c.Val() {
			case optionSelfAllowedIPs:
				p.selfAllowedIPs = make([]net.IPNet, 0)
				for _, aip := range c.RemainingArgs() {
					_, prefix, err := net.ParseCIDR(aip)
					if err != nil {
						return nil, fmt.Errorf("invalid self-allowed-ips: %s err: %v", c.Val(), err)
					}
					p.selfAllowedIPs = append(p.selfAllowedIPs, *prefix)
				}
			case optionSelfEndpoint:
				endpoint := c.RemainingArgs()
				if len(endpoint) != 1 {
					return nil, fmt.Errorf("expected 1 arg, got %d", len(endpoint))
				}
				host, portS, err := net.SplitHostPort(endpoint[0])
				if err != nil {
					return nil, fmt.Errorf("invalid self-endpoint, err: %v", err)
				}
				port, err := strconv.Atoi(portS)
				if err != nil {
					return nil, fmt.Errorf("error converting self-endpoint port: %v", err)
				}
				ip := net.ParseIP(host)
				if ip == nil {
					return nil, fmt.Errorf("invalid self-endpoint, invalid IP address: %s", host)
				}
				p.selfEndpoint = &net.UDPAddr{
					IP:   ip,
					Port: port,
				}
			default:
				return nil, c.ArgErr()
			}
		}
	}

	return p, nil
}

func setup(c *caddy.Controller) error {
	wgsd, err := parse(c)
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
	wgsd.client = client

	// Add the Plugin to CoreDNS, so Servers can use it in their plugin chain.
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		wgsd.Next = next
		return wgsd
	})

	return nil
}
