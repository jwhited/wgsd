package wgsd

import (
	"context"
	"encoding/base32"
	"encoding/base64"
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
	device *wgtypes.Device
}

func (m *mockClient) Device(d string) (*wgtypes.Device, error) {
	return m.device, nil
}

func constructAllowedIPs(t *testing.T, prefixes []string) ([]net.IPNet, string) {
	var allowed []net.IPNet
	var allowedString string
	for i, s := range prefixes {
		_, prefix, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatalf("error parsing cidr: %v", err)
		}
		allowed = append(allowed, *prefix)
		if i != 0 {
			allowedString += ","
		}
		allowedString += prefix.String()
	}
	return allowed, allowedString
}

func TestWGSD(t *testing.T) {
	selfKey := [32]byte{}
	selfKey[0] = 99
	selfb32 := strings.ToLower(base32.StdEncoding.EncodeToString(selfKey[:]))
	selfb64 := base64.StdEncoding.EncodeToString(selfKey[:])
	selfAllowed, selfAllowedString := constructAllowedIPs(t, []string{"10.0.0.99/32", "10.0.0.100/32"})
	key1 := [32]byte{}
	key1[0] = 1
	peer1Allowed, peer1AllowedString := constructAllowedIPs(t, []string{"10.0.0.1/32", "10.0.0.2/32"})
	peer1 := wgtypes.Peer{
		Endpoint: &net.UDPAddr{
			IP:   net.ParseIP("1.1.1.1"),
			Port: 1,
		},
		PublicKey:  key1,
		AllowedIPs: peer1Allowed,
	}
	peer1b32 := strings.ToLower(base32.StdEncoding.EncodeToString(peer1.PublicKey[:]))
	peer1b64 := base64.StdEncoding.EncodeToString(peer1.PublicKey[:])
	key2 := [32]byte{}
	key2[0] = 2
	peer2Allowed, peer2AllowedString := constructAllowedIPs(t, []string{"10.0.0.3/32", "10.0.0.4/32"})
	peer2 := wgtypes.Peer{
		Endpoint: &net.UDPAddr{
			IP:   net.ParseIP("::2"),
			Port: 2,
		},
		PublicKey:  key2,
		AllowedIPs: peer2Allowed,
	}
	peer2b32 := strings.ToLower(base32.StdEncoding.EncodeToString(peer2.PublicKey[:]))
	peer2b64 := base64.StdEncoding.EncodeToString(peer2.PublicKey[:])
	p := &WGSD{
		Next: test.ErrorHandler(),
		client: &mockClient{
			device: &wgtypes.Device{
				Name:       "wg0",
				PublicKey:  selfKey,
				ListenPort: 51820,
				Peers:      []wgtypes.Peer{peer1, peer2},
			},
		},
		zone:           "example.com.",
		device:         "wg0",
		selfAllowedIPs: selfAllowed,
	}

	testCases := []test.Case{
		{
			Qname: "_wireguard._udp.example.com.",
			Qtype: dns.TypePTR,
			Rcode: dns.RcodeSuccess,
			Answer: []dns.RR{
				test.PTR(fmt.Sprintf("_wireguard._udp.example.com. 0 IN PTR %s._wireguard._udp.example.com.", peer1b32)),
				test.PTR(fmt.Sprintf("_wireguard._udp.example.com. 0 IN PTR %s._wireguard._udp.example.com.", peer2b32)),
				test.PTR(fmt.Sprintf("_wireguard._udp.example.com. 0 IN PTR %s._wireguard._udp.example.com.", selfb32)),
			},
		},
		{
			Qname: fmt.Sprintf("%s._wireguard._udp.example.com.", selfb32),
			Qtype: dns.TypeSRV,
			Rcode: dns.RcodeSuccess,
			Answer: []dns.RR{
				test.SRV(fmt.Sprintf("%s._wireguard._udp.example.com. 0 IN SRV 0 0 51820 %s._wireguard._udp.example.com.", selfb32, selfb32)),
			},
			Extra: []dns.RR{
				test.A(fmt.Sprintf("%s._wireguard._udp.example.com. 0 IN A %s", selfb32, "127.0.0.1")),
				test.TXT(fmt.Sprintf(`%s._wireguard._udp.example.com. 0 IN TXT "txtvers=%d" "pub=%s" "allowed=%s"`, selfb32, txtVersion, selfb64, selfAllowedString)),
			},
		},
		{
			Qname: fmt.Sprintf("%s._wireguard._udp.example.com.", peer1b32),
			Qtype: dns.TypeSRV,
			Rcode: dns.RcodeSuccess,
			Answer: []dns.RR{
				test.SRV(fmt.Sprintf("%s._wireguard._udp.example.com. 0 IN SRV 0 0 1 %s._wireguard._udp.example.com.", peer1b32, peer1b32)),
			},
			Extra: []dns.RR{
				test.A(fmt.Sprintf("%s._wireguard._udp.example.com. 0 IN A %s", peer1b32, peer1.Endpoint.IP.String())),
				test.TXT(fmt.Sprintf(`%s._wireguard._udp.example.com. 0 IN TXT "txtvers=%d" "pub=%s" "allowed=%s"`, peer1b32, txtVersion, peer1b64, peer1AllowedString)),
			},
		},
		{
			Qname: fmt.Sprintf("%s._wireguard._udp.example.com.", peer2b32),
			Qtype: dns.TypeSRV,
			Rcode: dns.RcodeSuccess,
			Answer: []dns.RR{
				test.SRV(fmt.Sprintf("%s._wireguard._udp.example.com. 0 IN SRV 0 0 2 %s._wireguard._udp.example.com.", peer2b32, peer2b32)),
			},
			Extra: []dns.RR{
				test.AAAA(fmt.Sprintf("%s._wireguard._udp.example.com. 0 IN AAAA %s", peer2b32, peer2.Endpoint.IP.String())),
				test.TXT(fmt.Sprintf(`%s._wireguard._udp.example.com. 0 IN TXT "txtvers=%d" "pub=%s" "allowed=%s"`, peer2b32, txtVersion, peer2b64, peer2AllowedString)),
			},
		},
		{
			Qname: fmt.Sprintf("%s._wireguard._udp.example.com.", selfb32),
			Qtype: dns.TypeA,
			Rcode: dns.RcodeSuccess,
			Answer: []dns.RR{
				test.A(fmt.Sprintf("%s._wireguard._udp.example.com. 0 IN A %s", selfb32, "127.0.0.1")),
			},
		},
		{
			Qname: fmt.Sprintf("%s._wireguard._udp.example.com.", peer1b32),
			Qtype: dns.TypeA,
			Rcode: dns.RcodeSuccess,
			Answer: []dns.RR{
				test.A(fmt.Sprintf("%s._wireguard._udp.example.com. 0 IN A %s", peer1b32, peer1.Endpoint.IP.String())),
			},
		},
		{
			Qname: fmt.Sprintf("%s._wireguard._udp.example.com.", peer2b32),
			Qtype: dns.TypeAAAA,
			Rcode: dns.RcodeSuccess,
			Answer: []dns.RR{
				test.AAAA(fmt.Sprintf("%s._wireguard._udp.example.com. 0 IN AAAA %s", peer2b32, peer2.Endpoint.IP.String())),
			},
		},
		{
			Qname: fmt.Sprintf("%s._wireguard._udp.example.com.", selfb32),
			Qtype: dns.TypeTXT,
			Rcode: dns.RcodeSuccess,
			Answer: []dns.RR{
				test.TXT(fmt.Sprintf(`%s._wireguard._udp.example.com. 0 IN TXT "txtvers=%d" "pub=%s" "allowed=%s"`, selfb32, txtVersion, selfb64, selfAllowedString)),
			},
		},
		{
			Qname: fmt.Sprintf("%s._wireguard._udp.example.com.", peer1b32),
			Qtype: dns.TypeTXT,
			Rcode: dns.RcodeSuccess,
			Answer: []dns.RR{
				test.TXT(fmt.Sprintf(`%s._wireguard._udp.example.com. 0 IN TXT "txtvers=%d" "pub=%s" "allowed=%s"`, peer1b32, txtVersion, peer1b64, peer1AllowedString)),
			},
		},
		{
			Qname: fmt.Sprintf("%s._wireguard._udp.example.com.", peer2b32),
			Qtype: dns.TypeTXT,
			Rcode: dns.RcodeSuccess,
			Answer: []dns.RR{
				test.TXT(fmt.Sprintf(`%s._wireguard._udp.example.com. 0 IN TXT "txtvers=%d" "pub=%s" "allowed=%s"`, peer2b32, txtVersion, peer2b64, peer2AllowedString)),
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
