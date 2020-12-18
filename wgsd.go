package wgsd

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// coredns plugin-specific logger
var logger = clog.NewWithPlugin("wgsd")

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

	// the encoder used to encode wireguard peer public keys
	enc encoder
}

type wgctrlClient interface {
	Device(string) (*wgtypes.Device, error)
}

const (
	spPrefix = "_wireguard._udp."
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

	logger.Debugf("received query for: %s type: %s", name,
		dns.TypeToString[qtype])

	device, err := p.client.Device(p.device)
	if err != nil {
		return dns.RcodeServerFailure, err
	}
	if len(device.Peers) == 0 {
		return nxDomain(p.zone, w, r)
	}

	// setup our reply message
	m := &dns.Msg{}
	m.SetReply(r)
	m.Authoritative = true

	switch {
	// TODO: handle SOA
	case name == spPrefix && qtype == dns.TypePTR:
		for _, peer := range device.Peers {
			if peer.Endpoint == nil {
				continue
			}
			m.Answer = append(m.Answer, &dns.PTR{
				Hdr: dns.RR_Header{
					Name:   state.Name(),
					Rrtype: dns.TypePTR,
					Class:  dns.ClassINET,
					Ttl:    0,
				},
				Ptr: fmt.Sprintf("%s.%s%s",
					strings.ToLower(p.enc.EncodeToString(peer.PublicKey[:])),
					spPrefix, p.zone),
			})
		}
		_ = w.WriteMsg(m)
		return dns.RcodeSuccess, nil
	case qtype == dns.TypeSRV:
		pubKey := strings.TrimSuffix(name, "."+spPrefix)
		for _, peer := range device.Peers {
			if !strings.EqualFold(p.enc.EncodeToString(peer.PublicKey[:]), pubKey) {
				continue
			}
			endpoint := peer.Endpoint
			hostRR := getHostRR(pubKey, p.zone, endpoint)
			if hostRR == nil {
				return nxDomain(p.zone, w, r)
			}
			m.Extra = append(m.Extra, hostRR)
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
				Target: fmt.Sprintf("%s.%s",
					strings.ToLower(pubKey), p.zone),
			})
			_ = w.WriteMsg(m)
			return dns.RcodeSuccess, nil
		}
		return nxDomain(p.zone, w, r)
	case qtype == dns.TypeA || qtype == dns.TypeAAAA:
		pubKey := strings.TrimSuffix(name, ".")
		for _, peer := range device.Peers {
			if !strings.EqualFold(p.enc.EncodeToString(peer.PublicKey[:]), pubKey) {
				continue
			}
			endpoint := peer.Endpoint
			hostRR := getHostRR(pubKey, p.zone, endpoint)
			if hostRR == nil {
				return nxDomain(p.zone, w, r)
			}
			m.Answer = append(m.Answer, hostRR)
			_ = w.WriteMsg(m)
			return dns.RcodeSuccess, nil
		}
		return nxDomain(p.zone, w, r)
	default:
		return nxDomain(p.zone, w, r)
	}
}

func getHostRR(pubKey, zone string, endpoint *net.UDPAddr) dns.RR {
	if endpoint == nil || endpoint.IP == nil {
		return nil
	}
	name := fmt.Sprintf("%s.%s", strings.ToLower(pubKey), zone)
	switch {
	case endpoint.IP.To4() != nil:
		return &dns.A{
			Hdr: dns.RR_Header{
				Name:   name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    0,
			},
			A: endpoint.IP,
		}
	case endpoint.IP.To16() != nil:
		return &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   name,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    0,
			},
			AAAA: endpoint.IP,
		}
	default:
		// TODO: this shouldn't happen
		return nil
	}
}

func nxDomain(zone string, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Rcode = dns.RcodeNameError
	m.Ns = []dns.RR{soa(zone)}
	_ = w.WriteMsg(m)
	return dns.RcodeSuccess, nil
}

func soa(zone string) dns.RR {
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   zone,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		Ns:      fmt.Sprintf("ns1.%s", zone),
		Mbox:    fmt.Sprintf("postmaster.%s", zone),
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
