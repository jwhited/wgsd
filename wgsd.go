package wgsd

import (
	"context"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

// WGSD is a CoreDNS plugin that provides Wireguard peer information via DNS-SD
// semantics. WGSD implements the plugin.Handler interface.
type WGSD struct {
	Next plugin.Handler
}

func (w *WGSD) ServeDNS(ctx context.Context, rw dns.ResponseWriter,
	msg *dns.Msg) (int, error) {
	return plugin.NextOrFailure(w.Name(), w.Next, ctx, rw, msg)
}

func (w *WGSD) Name() string {
	return "wgsd"
}
