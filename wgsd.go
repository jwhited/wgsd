package wgsd

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// WGSD is a CoreDNS plugin that provides Wireguard peer information via DNS-SD
// semantics. WGSD implements the plugin.Handler interface.
type WGSD struct {
	Next plugin.Handler

	// the client for retrieving Wireguard peer information
	client wgctrlClient
	// the DNS zone we are serving records for
	zone string
	// the Wireguard device name, e.g. wg0
	device string
}

type wgctrlClient interface {
	Device(string) (*wgtypes.Device, error)
}

const (
	keyLen             = 44 // the number of characters in a base64-encoded Wireguard public key
	spPrefix           = "_wireguard._udp."
	serviceInstanceLen = keyLen + len(".") + len(spPrefix)
)

func (p *WGSD) ServeDNS(ctx context.Context, w dns.ResponseWriter,
	r *dns.Msg) (int, error) {
	// request.Request is a convenience struct we wrap around the msg and
	// ResponseWriter.
	state := request.Request{W: w, Req: r}

	// Check if the request is for the zone we are serving. If it doesn't match
	// we pass the request on to the next plugin.
	if plugin.Zones([]string{p.zone}).Matches(state.Name()) == "" {
		return plugin.NextOrFailure(p.Name(), p.Next, ctx, w, r)
	}

	// strip zone from name
	name := strings.TrimSuffix(state.Name(), p.zone)
	qtype := state.QType()

	device, err := p.client.Device(p.device)
	if err != nil {
		return dns.RcodeServerFailure, nil
	}
	if len(device.Peers) == 0 {
		return nxdomain(p.zone, w, r)
	}

	// setup our reply message
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	switch {
	case name == spPrefix && qtype == dns.TypePTR:
		for _, peer := range device.Peers {
			m.Answer = append(m.Answer, &dns.PTR{
				Hdr: dns.RR_Header{
					Name:   state.Name(),
					Rrtype: dns.TypePTR,
					Class:  dns.ClassINET,
					Ttl:    0,
				},
				Ptr: fmt.Sprintf("%s.%s",
					base64.StdEncoding.EncodeToString(peer.PublicKey[:]),
					p.zone),
			})
		}
		w.WriteMsg(m) // nolint: errcheck
		return dns.RcodeSuccess, nil
	case len(name) == serviceInstanceLen && qtype == dns.TypeSRV:
		pubKey := name[:44]
		for _, peer := range device.Peers {
			if base64.StdEncoding.EncodeToString(peer.PublicKey[:]) == pubKey {
				endpoint := peer.Endpoint
				if endpoint.IP == nil {
					return nxdomain(p.zone, w, r)
				}
				srvTarget := fmt.Sprintf("%s.%s", pubKey, p.zone)
				m.Answer = append(m.Answer, &dns.SRV{
					Hdr: dns.RR_Header{
						Name:   state.Name(),
						Rrtype: dns.TypeSRV,
						Class:  dns.ClassINET,
						Ttl:    0,
					},
					Priority: 0,
					Weight:   0,
					Port:     uint16(endpoint.Port),
					Target:   srvTarget,
				})
				switch {
				case endpoint.IP.To4() != nil:
					m.Extra = append(m.Extra, &dns.A{
						Hdr: dns.RR_Header{
							Name:   srvTarget,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    0,
						},
						A: endpoint.IP,
					})
				case endpoint.IP.To16() != nil:
					m.Extra = append(m.Extra, &dns.AAAA{
						Hdr: dns.RR_Header{
							Name:   srvTarget,
							Rrtype: dns.TypeAAAA,
							Class:  dns.ClassINET,
							Ttl:    0,
						},
						AAAA: endpoint.IP,
					})
				default:
					// TODO: this shouldn't happen
				}
				w.WriteMsg(m) // nolint: errcheck
				return dns.RcodeSuccess, nil
			}
		}
		return nxdomain(p.zone, w, r)
	case len(name) == keyLen+len(".") && (qtype == dns.TypeA ||
		qtype == dns.TypeAAAA):
		// TODO: return A/AAAA for of peer
	default:
		return nxdomain(p.zone, w, r)
	}

	w.WriteMsg(m) // nolint: errcheck
	return dns.RcodeSuccess, nil
}

func nxdomain(name string, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Rcode = dns.RcodeNameError
	m.Ns = []dns.RR{soa(name)}
	w.WriteMsg(m) // nolint: errcheck
	return dns.RcodeSuccess, nil
}

func soa(name string) dns.RR {
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		Ns:      fmt.Sprintf("ns1.%s", name),
		Mbox:    fmt.Sprintf("postmaster.%s", name),
		Serial:  1,
		Refresh: 86400,
		Retry:   7200,
		Expire:  3600000,
		Minttl:  60,
	}
}

func (p *WGSD) Name() string {
	return "wgsd"
}
