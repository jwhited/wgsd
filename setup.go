package wgsd

import (
	"fmt"
	"net"

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
		return plugin.Error("wgsd", c.ArgErr())
	}
	zone := dns.Fqdn(c.Val())

	// return an error if there is no device name specified
	if !c.NextArg() {
		return plugin.Error("wgsd", c.ArgErr())
	}
	device := c.Val()

	// parse optional local ip
	var wgIP net.IP
	if c.NextArg() {
		wgIP = net.ParseIP(c.Val())
	} else {
		wgIP = getOutboundIP()
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
			wgIP:   wgIP,
		}
	})

	return nil
}

// Get preferred outbound ip of this machine
func getOutboundIP() net.IP {
	conn, err := net.Dial("udp", "1.1.1.1:80")
	if err != nil {
		return nil
	}
	defer conn.Close()

	return conn.LocalAddr().(*net.UDPAddr).IP
}
