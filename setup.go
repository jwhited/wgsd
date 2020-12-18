package wgsd

import (
	"fmt"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
	"golang.zx2c4.com/wireguard/wgctrl"
)

func init() {
	plugin.Register("wgsd", setup)
}

func setup(c *caddy.Controller) error {
	c.Next() // Ignore "wgsd" and give us the next token.

	// return an error if there is no zone specified
	if !c.NextArg() {
		return plugin.Error("wgsd", fmt.Errorf("missing zone: %v", c.ArgErr()))
	}
	zone := dns.Fqdn(c.Val())

	// return an error if there is no device name specified
	if !c.NextArg() {
		return plugin.Error("wgsd", fmt.Errorf("missing wireguard device name: %v", c.ArgErr()))
	}
	device := c.Val()

	if !c.NextArg() {
		return plugin.Error("wgsd", fmt.Errorf("missing wireguard public key encoding: %v", c.ArgErr()))
	}
	enc, err := getEncoder(c.Val())
	if err != nil {
		return plugin.Error("wgsd", fmt.Errorf("unsupported wireguard public key encoding: %v", err))
	}

	// return an error if there are more tokens on this line
	if c.NextArg() {
		return plugin.Error("wgsd", c.ArgErr())
	}

	client, err := wgctrl.New()
	if err != nil {
		return plugin.Error("wgsd",
			fmt.Errorf("error constructing wgctrl client: %v",
				err))
	}

	// Add the Plugin to CoreDNS, so Servers can use it in their plugin chain.
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return &WGSD{
			Next:   next,
			client: client,
			zone:   zone,
			device: device,
			enc:    enc,
		}
	})

	return nil
}
