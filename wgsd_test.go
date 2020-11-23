package wgsd

import (
	"context"
	"encoding/base32"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type mockClient struct {
	peers []wgtypes.Peer
}

func (m *mockClient) Device(d string) (*wgtypes.Device, error) {
	return &wgtypes.Device{
		Name:  d,
		Peers: m.peers,
	}, nil
}

func TestWGSD(t *testing.T) {
	key1 := [32]byte{}
	key1[0] = 1
	peer1 := wgtypes.Peer{
		Endpoint: &net.UDPAddr{
			IP:   net.ParseIP("1.1.1.1"),
			Port: 1,
		},
		PublicKey: key1,
	}
	peer1b32 := strings.ToLower(base32.StdEncoding.EncodeToString(peer1.PublicKey[:]))
	key2 := [32]byte{}
	key2[0] = 2
	peer2 := wgtypes.Peer{
		Endpoint: &net.UDPAddr{
			IP:   net.ParseIP("::2"),
			Port: 2,
		},
		PublicKey: key2,
	}
	peer2b32 := strings.ToLower(base32.StdEncoding.EncodeToString(peer2.PublicKey[:]))
	p := &WGSD{
		Next: test.ErrorHandler(),
		client: &mockClient{
			peers: []wgtypes.Peer{peer1, peer2},
		},
		zone:   "example.com.",
		device: "wg0",
	}

	testCases := []test.Case{
		{
			Qname: "_wireguard._udp.example.com.",
			Qtype: dns.TypePTR,
			Rcode: dns.RcodeSuccess,
			Answer: []dns.RR{
				test.PTR(fmt.Sprintf("_wireguard._udp.example.com. 0 IN PTR %s._wireguard._udp.example.com.", peer1b32)),
				test.PTR(fmt.Sprintf("_wireguard._udp.example.com. 0 IN PTR %s._wireguard._udp.example.com.", peer2b32)),
			},
		},
		{
			Qname: fmt.Sprintf("%s._wireguard._udp.example.com.", peer1b32),
			Qtype: dns.TypeSRV,
			Rcode: dns.RcodeSuccess,
			Answer: []dns.RR{
				test.SRV(fmt.Sprintf("%s._wireguard._udp.example.com. 0 IN SRV 0 0 1 %s.example.com.", peer1b32, peer1b32)),
			},
			Extra: []dns.RR{
				test.A(fmt.Sprintf("%s.example.com. 0 IN A %s", peer1b32, peer1.Endpoint.IP.String())),
			},
		},
		{
			Qname: fmt.Sprintf("%s._wireguard._udp.example.com.", peer2b32),
			Qtype: dns.TypeSRV,
			Rcode: dns.RcodeSuccess,
			Answer: []dns.RR{
				test.SRV(fmt.Sprintf("%s._wireguard._udp.example.com. 0 IN SRV 0 0 2 %s.example.com.", peer2b32, peer2b32)),
			},
			Extra: []dns.RR{
				test.AAAA(fmt.Sprintf("%s.example.com. 0 IN AAAA %s", peer2b32, peer2.Endpoint.IP.String())),
			},
		},
		{
			Qname: fmt.Sprintf("%s.example.com.", peer1b32),
			Qtype: dns.TypeA,
			Rcode: dns.RcodeSuccess,
			Answer: []dns.RR{
				test.A(fmt.Sprintf("%s.example.com. 0 IN A %s", peer1b32, peer1.Endpoint.IP.String())),
			},
		},
		{
			Qname: fmt.Sprintf("%s.example.com.", peer2b32),
			Qtype: dns.TypeAAAA,
			Rcode: dns.RcodeSuccess,
			Answer: []dns.RR{
				test.AAAA(fmt.Sprintf("%s.example.com. 0 IN AAAA %s", peer2b32, peer2.Endpoint.IP.String())),
			},
		},
		{
			Qname: "nxdomain.example.com.",
			Qtype: dns.TypeAAAA,
			Rcode: dns.RcodeNameError,
			Ns: []dns.RR{
				test.SOA(soa("example.com.").String()),
			},
		},
		{
			Qname: "servfail.notexample.com.",
			Qtype: dns.TypeAAAA,
			Rcode: dns.RcodeServerFailure,
		},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s %s", tc.Qname, dns.TypeToString[tc.Qtype]), func(t *testing.T) {
			m := tc.Msg()
			rec := dnstest.NewRecorder(&test.ResponseWriter{})
			ctx := context.TODO()
			_, err := p.ServeDNS(ctx, rec, m)
			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}
			resp := rec.Msg
			if err := test.Header(tc, resp); err != nil {
				t.Error(err)
				return
			}
			if err := test.Section(tc, test.Answer, resp.Answer); err != nil {
				t.Error(err)
			}
			if err := test.Section(tc, test.Ns, resp.Ns); err != nil {
				t.Error(err)
			}
			if err := test.Section(tc, test.Extra, resp.Extra); err != nil {
				t.Error(err)
			}
		})
	}
}
