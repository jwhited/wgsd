package wgsd

import (
	"net"
	"reflect"
	"testing"

	"github.com/coredns/caddy"
)

func TestSetup(t *testing.T) {
	testCases := []struct {
		name                 string
		input                string
		expectErr            bool
		expectSelfAllowedIPs []string
		expectSelfEndpoint   *net.UDPAddr
	}{
		{
			"valid input",
			"wgsd example.com. wg0",
			false,
			nil,
			nil,
		},
		{
			"missing token",
			"wgsd example.com.",
			true,
			nil,
			nil,
		},
		{
			"too many tokens",
			"wgsd example.com. wg0 extra",
			true,
			nil,
			nil,
		},
		{
			"valid self-allowed-ips",
			`wgsd example.com. wg0 {
						self-allowed-ips 10.0.0.1/32 10.0.0.2/32
					}`,
			false,
			[]string{"10.0.0.1/32", "10.0.0.2/32"},
			nil,
		},
		{
			"invalid self-allowed-ips",
			`wgsd example.com. wg0 {
						self-allowed-ips 10.0.01/32 10.0.0.2/32
					}`,
			true,
			nil,
			nil,
		},
		{
			"valid self-endpoint",
			`wgsd example.com. wg0 {
						self-endpoint 127.0.0.1:51820
					}`,
			false,
			nil,
			&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 51820},
		},
		{
			"invalid self-endpoint",
			`wgsd example.com. wg0 {
						self-endpoint hostname:51820
					}`,
			true,
			nil,
			nil,
		},
		{
			"all options",
			`wgsd example.com. wg0 {
						self-allowed-ips 10.0.0.1/32 10.0.0.2/32
						self-endpoint 127.0.0.1:51820
					}`,
			false,
			[]string{"10.0.0.1/32", "10.0.0.2/32"},
			&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 51820},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := caddy.NewTestController("dns", tc.input)
			wgsd, err := parse(c)
			if (err != nil) != tc.expectErr {
				t.Fatalf("expectErr: %v, got err=%v", tc.expectErr, err)
			}
			if tc.expectErr {
				return
			}
			if !reflect.DeepEqual(wgsd.selfEndpoint, tc.expectSelfEndpoint) {
				t.Errorf("expected self-endpoint %s but found: %s", tc.expectSelfEndpoint, wgsd.selfEndpoint)
			}
			var expectSelfAllowedIPs []net.IPNet
			if tc.expectSelfAllowedIPs != nil {
				expectSelfAllowedIPs = make([]net.IPNet, 0)
				for _, s := range tc.expectSelfAllowedIPs {
					_, p, _ := net.ParseCIDR(s)
					expectSelfAllowedIPs = append(expectSelfAllowedIPs, *p)
				}
			}
			if !reflect.DeepEqual(wgsd.selfAllowedIPs, expectSelfAllowedIPs) {
				t.Errorf("expected self-allowed-ips %s but found: %s", expectSelfAllowedIPs, wgsd.selfAllowedIPs)
			}
		})
	}
}
