package wgsd

import (
	"fmt"

	"github.com/caddyserver/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"golang.zx2c4.com/wireguard/wgctrl"
)

func init() {
	plugin.Register("wgsd", setup)
}

func setup(c *caddy.Controller) error {
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wgsd: error constructing wgctrl client: %v",
			err)
	}

	// TODO: parse zone and wireguard device name from config

	// Add the Plugin to CoreDNS, so Servers can use it in their plugin chain.
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return &WGSD{
			Next:   next,
			client: client,
		}
	})

	return nil
}
