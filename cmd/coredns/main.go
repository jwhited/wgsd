package main

import (
	_ "github.com/coredns/coredns/core/plugin"
	_ "github.com/jwhited/wgsd"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/coremain"
)

func init() {
	// plugin ordering matters, insert wgsd with other "authoritative" plugins.
	for i, name := range dnsserver.Directives {
		if name == "file" {
			dnsserver.Directives = append(dnsserver.Directives[:i],
				append([]string{"wgsd"}, dnsserver.Directives[i:]...)...)
			return
		}
	}
	panic("file plugin not found in dnsserver.Directives")
}

func main() {
	coremain.Run()
}
