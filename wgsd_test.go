package wgsd

import (
	"bytes"
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
	host  wgtypes.Peer
	peers []wgtypes.Peer
}

func (m *mockClient) Device(d string) (*wgtypes.Device, error) {
	return &wgtypes.Device{
		Name:       d,
		PublicKey:  m.host.PublicKey,
		ListenPort: m.host.Endpoint.Port,
		Peers:      m.peers,
	}, nil
}

func base32EqualsPubKey(t *testing.T, b32 string, pubKey wgtypes.Key) bool {
	got, err := base32.StdEncoding.DecodeString(strings.ToUpper(b32))
	if err != nil {
		t.Fatalf("error decoding base32 string: %v", err)
	}
	return bytes.Equal(pubKey[:], got)
}

func TestWGSD(t *testing.T) {
	hostkey := [32]byte{}
	hostkey[0] = 1
	host := wgtypes.Peer{
		Endpoint: &net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 1,
		},
		PublicKey: hostkey,
	}
	hostb32 := strings.ToLower(base32.StdEncoding.EncodeToString(host.PublicKey[:]))
	key1 := [32]byte{}
	key1[0] = 2
	peer1 := wgtypes.Peer{
		Endpoint: &net.UDPAddr{
			IP:   net.ParseIP("1.1.1.1"),
			Port: 2,
		},
		PublicKey: key1,
	}
	peer1b32 := strings.ToLower(base32.StdEncoding.EncodeToString(peer1.PublicKey[:]))
	key2 := [32]byte{}
	key2[0] = 3
	peer2 := wgtypes.Peer{
		Endpoint: &net.UDPAddr{
			IP:   net.ParseIP("::2"),
			Port: 3,
		},
		PublicKey: key2,
	}
	peer2b32 := strings.ToLower(base32.StdEncoding.EncodeToString(peer2.PublicKey[:]))
	p := &WGSD{
		Next: test.ErrorHandler(),
		client: &mockClient{
			host:  host,
			peers: []wgtypes.Peer{peer1, peer2},
		},
		zone:   "example.com.",
		device: "wg0",
		wgIP:   host.Endpoint.IP,
	}

	testCases := []test.Case{
		test.Case{
			Qname: "_wireguard._udp.example.com.",
			Qtype: dns.TypePTR,
			Rcode: dns.RcodeSuccess,
			Answer: []dns.RR{
				test.PTR(fmt.Sprintf("_wireguard._udp.example.com. 0 IN PTR %s._wireguard._udp.example.com.", hostb32)),
				test.PTR(fmt.Sprintf("_wireguard._udp.example.com. 0 IN PTR %s._wireguard._udp.example.com.", peer1b32)),
				test.PTR(fmt.Sprintf("_wireguard._udp.example.com. 0 IN PTR %s._wireguard._udp.example.com.", peer2b32)),
			},
		},
		test.Case{
			Qname: fmt.Sprintf("_wireguard._udp.example.com."),
			Qtype: dns.TypeSRV,
			Rcode: dns.RcodeSuccess,
			Answer: []dns.RR{
				test.SRV(fmt.Sprintf("_wireguard._udp.example.com. 0 IN SRV 0 0 1 %s.example.com.", hostb32)),
			},
			Extra: []dns.RR{
				test.A(fmt.Sprintf("%s.example.com. 0 IN A %s", hostb32, host.Endpoint.IP.String())),
			},
		},
		test.Case{
			Qname: fmt.Sprintf("%s._wireguard._udp.example.com.", hostb32),
			Qtype: dns.TypeSRV,
			Rcode: dns.RcodeSuccess,
			Answer: []dns.RR{
				test.SRV(fmt.Sprintf("%s._wireguard._udp.example.com. 0 IN SRV 0 0 1 %s.example.com.", hostb32, hostb32)),
			},
			Extra: []dns.RR{
				test.A(fmt.Sprintf("%s.example.com. 0 IN A %s", hostb32, host.Endpoint.IP.String())),
			},
		},
		test.Case{
			Qname: fmt.Sprintf("%s._wireguard._udp.example.com.", peer1b32),
			Qtype: dns.TypeSRV,
			Rcode: dns.RcodeSuccess,
			Answer: []dns.RR{
				test.SRV(fmt.Sprintf("%s._wireguard._udp.example.com. 0 IN SRV 0 0 2 %s.example.com.", peer1b32, peer1b32)),
			},
			Extra: []dns.RR{
				test.A(fmt.Sprintf("%s.example.com. 0 IN A %s", peer1b32, peer1.Endpoint.IP.String())),
			},
		},
		test.Case{
			Qname: fmt.Sprintf("%s._wireguard._udp.example.com.", peer2b32),
			Qtype: dns.TypeSRV,
			Rcode: dns.RcodeSuccess,
			Answer: []dns.RR{
				test.SRV(fmt.Sprintf("%s._wireguard._udp.example.com. 0 IN SRV 0 0 3 %s.example.com.", peer2b32, peer2b32)),
			},
			Extra: []dns.RR{
				test.AAAA(fmt.Sprintf("%s.example.com. 0 IN AAAA %s", peer2b32, peer2.Endpoint.IP.String())),
			},
		},
		test.Case{
			Qname: fmt.Sprintf("%s.example.com.", hostb32),
			Qtype: dns.TypeA,
			Rcode: dns.RcodeSuccess,
			Answer: []dns.RR{
				test.A(fmt.Sprintf("%s.example.com. 0 IN A %s", hostb32, host.Endpoint.IP.String())),
			},
		},
		test.Case{
			Qname: fmt.Sprintf("%s.example.com.", peer1b32),
			Qtype: dns.TypeA,
			Rcode: dns.RcodeSuccess,
			Answer: []dns.RR{
				test.A(fmt.Sprintf("%s.example.com. 0 IN A %s", peer1b32, peer1.Endpoint.IP.String())),
			},
		},
		test.Case{
			Qname: fmt.Sprintf("%s.example.com.", peer2b32),
			Qtype: dns.TypeAAAA,
			Rcode: dns.RcodeSuccess,
			Answer: []dns.RR{
				test.AAAA(fmt.Sprintf("%s.example.com. 0 IN AAAA %s", peer2b32, peer2.Endpoint.IP.String())),
			},
		},
		test.Case{
			Qname: "nxdomain.example.com.",
			Qtype: dns.TypeAAAA,
			Rcode: dns.RcodeNameError,
			Ns: []dns.RR{
				test.SOA(soa("example.com.").String()),
			},
		},
		test.Case{
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
