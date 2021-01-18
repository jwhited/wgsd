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
var logger = clog.NewWithPlugin(pluginName)

const (
	pluginName = "wgsd"
)

// WGSD is a CoreDNS plugin that provides WireGuard peer information via DNS-SD
// semantics. WGSD implements the plugin.Handler interface.
type WGSD struct {
	Next plugin.Handler
	Zones
	client wgctrlClient // the client for retrieving WireGuard peer information
}

type Zones struct {
	Z     map[string]*Zone // a mapping from zone name to zone data
	Names []string         // all keys from the map z as a string slice
}

type Zone struct {
	name           string       // the name of the zone we are authoritative for
	device         string       // the WireGuard device name, e.g. wg0
	serveSelf      bool         // flag to enable serving data about self
	selfEndpoint   *net.UDPAddr // overrides the self endpoint value
	selfAllowedIPs []net.IPNet  // self allowed IPs
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

type handlerFn func(state request.Request, peers []wgtypes.Peer) (int, error)

func getHandlerFn(queryType uint16, name string) handlerFn {
	switch {
	case name == spPrefix && queryType == dns.TypePTR:
		return handlePTR
	case len(name) == serviceInstanceLen && queryType == dns.TypeSRV:
		return handleSRV
	case len(name) == len(spSubPrefix)+keyLen && (queryType == dns.TypeA ||
		queryType == dns.TypeAAAA || queryType == dns.TypeTXT):
		return handleHostOrTXT
	default:
		return nil
	}
}

func handlePTR(state request.Request, peers []wgtypes.Peer) (int, error) {
	m := new(dns.Msg)
	m.SetReply(state.Req)
	m.Authoritative = true
	for _, peer := range peers {
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
				spPrefix, state.Zone),
		})
	}
	state.W.WriteMsg(m) // nolint: errcheck
	return dns.RcodeSuccess, nil
}

func handleSRV(state request.Request, peers []wgtypes.Peer) (int, error) {
	m := new(dns.Msg)
	m.SetReply(state.Req)
	m.Authoritative = true
	pubKey := state.Name()[:keyLen]
	for _, peer := range peers {
		if strings.EqualFold(
			base32.StdEncoding.EncodeToString(peer.PublicKey[:]), pubKey) {
			endpoint := peer.Endpoint
			if endpoint == nil {
				return nxDomain(state)
			}
			hostRR := getHostRR(state.Name(), endpoint)
			if hostRR == nil {
				return nxDomain(state)
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
			state.W.WriteMsg(m) // nolint: errcheck
			return dns.RcodeSuccess, nil
		}
	}
	return nxDomain(state)
}

func handleHostOrTXT(state request.Request, peers []wgtypes.Peer) (int, error) {
	m := new(dns.Msg)
	m.SetReply(state.Req)
	m.Authoritative = true
	pubKey := state.Name()[:keyLen]
	for _, peer := range peers {
		if strings.EqualFold(
			base32.StdEncoding.EncodeToString(peer.PublicKey[:]), pubKey) {
			endpoint := peer.Endpoint
			if endpoint == nil {
				return nxDomain(state)
			}
			if state.QType() == dns.TypeA || state.QType() == dns.TypeAAAA {
				hostRR := getHostRR(state.Name(), endpoint)
				if hostRR == nil {
					return nxDomain(state)
				}
				m.Answer = append(m.Answer, hostRR)
			} else {
				txtRR := getTXTRR(state.Name(), peer)
				m.Answer = append(m.Answer, txtRR)
			}
			state.W.WriteMsg(m) // nolint: errcheck
			return dns.RcodeSuccess, nil
		}
	}
	return nxDomain(state)
}

func getSelfPeer(zone *Zone, device *wgtypes.Device, state request.Request) (wgtypes.Peer, error) {
	self := wgtypes.Peer{
		PublicKey: device.PublicKey,
	}
	if zone.selfEndpoint != nil {
		self.Endpoint = zone.selfEndpoint
	} else {
		self.Endpoint = &net.UDPAddr{
			IP:   net.ParseIP(state.LocalIP()),
			Port: device.ListenPort,
		}
	}
	self.AllowedIPs = zone.selfAllowedIPs
	return self, nil
}

func getPeers(client wgctrlClient, zone *Zone, state request.Request) (
	[]wgtypes.Peer, error) {
	peers := make([]wgtypes.Peer, 0)
	device, err := client.Device(zone.device)
	if err != nil {
		return nil, err
	}
	peers = append(peers, device.Peers...)
	if zone.serveSelf {
		self, err := getSelfPeer(zone, device, state)
		if err != nil {
			return nil, err
		}
		peers = append(peers, self)
	}
	return peers, nil
}

func (p *WGSD) ServeDNS(ctx context.Context, w dns.ResponseWriter,
	r *dns.Msg) (int, error) {
	// request.Request is a convenience struct we wrap around the msg and
	// ResponseWriter.
	state := request.Request{W: w, Req: r}

	// Check if the request is for a zone we are serving. If it doesn't match we
	// pass the request on to the next plugin.
	zoneName := plugin.Zones(p.Names).Matches(state.Name())
	if zoneName == "" {
		return plugin.NextOrFailure(p.Name(), p.Next, ctx, w, r)
	}
	state.Zone = zoneName

	zone, ok := p.Z[zoneName]
	if !ok {
		return dns.RcodeServerFailure, nil
	}

	// strip zone from name
	name := strings.TrimSuffix(state.Name(), zoneName)
	queryType := state.QType()

	logger.Debugf("received query for: %s type: %s", name,
		dns.TypeToString[queryType])

	handler := getHandlerFn(queryType, name)
	if handler == nil {
		return nxDomain(state)
	}

	peers, err := getPeers(p.client, zone, state)
	if err != nil {
		return dns.RcodeServerFailure, err
	}

	return handler(state, peers)
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

func nxDomain(state request.Request) (int, error) {
	m := new(dns.Msg)
	m.SetReply(state.Req)
	m.Authoritative = true
	m.Rcode = dns.RcodeNameError
	m.Ns = []dns.RR{soa(state.Zone)}
	state.W.WriteMsg(m) // nolint: errcheck
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
	return pluginName
}
