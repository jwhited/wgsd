package wgsd

import (
	"context"
	"encoding/base32"
	"encoding/base64"
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

// WGSD is a CoreDNS plugin that provides WireGuard peer information via DNS-SD
// semantics. WGSD implements the plugin.Handler interface.
type WGSD struct {
	Next plugin.Handler

	// the client for retrieving WireGuard peer information
	client wgctrlClient
	// the DNS zone we are serving records for
	zone string
	// the WireGuard device name, e.g. wg0
	device string
}

type wgctrlClient interface {
	Device(string) (*wgtypes.Device, error)
}

const (
	keyLen             = 56 // the number of characters in a base32-encoded WireGuard public key
	spPrefix           = "_wireguard._udp."
	spSubPrefix        = "." + spPrefix
	serviceInstanceLen = keyLen + len(spSubPrefix)
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
	qType := state.QType()

	logger.Debugf("received query for: %s type: %s", name,
		dns.TypeToString[qType])

	device, err := p.client.Device(p.device)
	if err != nil {
		return dns.RcodeServerFailure, err
	}
	if len(device.Peers) == 0 {
		return nxDomain(p.zone, w, r)
	}

	// setup our reply message
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	switch {
	// TODO: handle SOA
	case name == spPrefix && qType == dns.TypePTR:
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
					strings.ToLower(base32.StdEncoding.EncodeToString(peer.PublicKey[:])),
					spPrefix, p.zone),
			})
		}
		w.WriteMsg(m) // nolint: errcheck
		return dns.RcodeSuccess, nil
	case len(name) == serviceInstanceLen && qType == dns.TypeSRV:
		pubKey := name[:keyLen]
		for _, peer := range device.Peers {
			if strings.EqualFold(
				base32.StdEncoding.EncodeToString(peer.PublicKey[:]), pubKey) {
				endpoint := peer.Endpoint
				hostRR := getHostRR(state.Name(), endpoint)
				if hostRR == nil {
					return nxDomain(p.zone, w, r)
				}
				txtRR := getTXTRR(state.Name(), peer)
				m.Extra = append(m.Extra, hostRR, txtRR)
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
					Target:   state.Name(),
				})
				w.WriteMsg(m) // nolint: errcheck
				return dns.RcodeSuccess, nil
			}
		}
		return nxDomain(p.zone, w, r)
	case len(name) == len(spSubPrefix)+keyLen && (qType == dns.TypeA ||
		qType == dns.TypeAAAA || qType == dns.TypeTXT):
		pubKey := name[:keyLen]
		for _, peer := range device.Peers {
			if strings.EqualFold(
				base32.StdEncoding.EncodeToString(peer.PublicKey[:]), pubKey) {
				endpoint := peer.Endpoint
				if qType == dns.TypeA || qType == dns.TypeAAAA {
					hostRR := getHostRR(state.Name(), endpoint)
					if hostRR == nil {
						return nxDomain(p.zone, w, r)
					}
					m.Answer = append(m.Answer, hostRR)
				} else {
					txtRR := getTXTRR(state.Name(), peer)
					m.Answer = append(m.Answer, txtRR)
				}
				w.WriteMsg(m) // nolint: errcheck
				return dns.RcodeSuccess, nil
			}
		}
		return nxDomain(p.zone, w, r)
	default:
		return nxDomain(p.zone, w, r)
	}
}

func getHostRR(name string, endpoint *net.UDPAddr) dns.RR {
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

const (
	// txtVersion is the first key/value pair in the TXT RR. Its serves to aid
	// clients with maintaining backwards compatibility.
	//
	// https://tools.ietf.org/html/rfc6763#section-6.7
	txtVersion = 1
)

func getTXTRR(name string, peer wgtypes.Peer) *dns.TXT {
	var allowedIPs string
	for i, prefix := range peer.AllowedIPs {
		if i != 0 {
			allowedIPs += ","
		}
		allowedIPs += prefix.String()
	}
	return &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		Txt: []string{
			fmt.Sprintf("txtvers=%d", txtVersion),
			fmt.Sprintf("pub=%s",
				base64.StdEncoding.EncodeToString(peer.PublicKey[:])),
			fmt.Sprintf("allowed=%s", allowedIPs),
		},
	}
}

func nxDomain(zone string, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Rcode = dns.RcodeNameError
	m.Ns = []dns.RR{soa(zone)}
	w.WriteMsg(m) // nolint: errcheck
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
