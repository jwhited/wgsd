package wgsd

import (
	"net"
	"reflect"
	"testing"

	"github.com/coredns/caddy"
)

func TestSetup(t *testing.T) {
	_, prefix1, _ := net.ParseCIDR("1.1.1.1/32")
	_, prefix2, _ := net.ParseCIDR("2.2.2.2/32")
	_, prefix3, _ := net.ParseCIDR("3.3.3.3/32")
	_, prefix4, _ := net.ParseCIDR("4.4.4.4/32")
	endpoint1 := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 51820}

	testCases := []struct {
		name          string
		input         string
		shouldErr     bool
		expectedZones Zones
	}{
		{
			"valid input",
			"wgsd example.com. wg0",
			false,
			Zones{
				Z: map[string]*Zone{
					"example.com.": {
						name:   "example.com.",
						device: "wg0",
					},
				},
				Names: []string{"example.com."},
			},
		},
		{
			"missing token",
			"wgsd example.com.",
			true,
			Zones{},
		},
		{
			"too many tokens",
			"wgsd example.com. wg0 extra",
			true,
			Zones{},
		},
		{
			"valid self allowed-ips",
			`wgsd example.com. wg0 {
						self 1.1.1.1/32 2.2.2.2/32
					}`,
			false,
			Zones{
				Z: map[string]*Zone{
					"example.com.": {
						name:           "example.com.",
						device:         "wg0",
						serveSelf:      true,
						selfAllowedIPs: []net.IPNet{*prefix1, *prefix2},
					},
				},
				Names: []string{"example.com."},
			},
		},
		{
			"invalid self-allowed-ips",
			`wgsd example.com. wg0 {
						self 1.1.11/32 2.2.2.2/32
					}`,
			true,
			Zones{},
		},
		{
			"valid self-endpoint",
			`wgsd example.com. wg0 {
						self 127.0.0.1:51820
					}`,
			false,
			Zones{
				Z: map[string]*Zone{
					"example.com.": {
						name:         "example.com.",
						device:       "wg0",
						serveSelf:    true,
						selfEndpoint: endpoint1,
					},
				},
				Names: []string{"example.com."},
			},
		},
		{
			"invalid self-endpoint",
			`wgsd example.com. wg0 {
						self hostname:51820
					}`,
			true,
			Zones{},
		},
		{
			"multiple blocks",
			`wgsd example.com. wg0 {
						self 127.0.0.1:51820 1.1.1.1/32 2.2.2.2/32
					}
					wgsd example2.com. wg1 {
						self 127.0.0.1:51820 3.3.3.3/32 4.4.4.4/32
					}`,
			false,
			Zones{
				Z: map[string]*Zone{
					"example.com.": {
						name:           "example.com.",
						device:         "wg0",
						serveSelf:      true,
						selfEndpoint:   endpoint1,
						selfAllowedIPs: []net.IPNet{*prefix1, *prefix2},
					},
					"example2.com.": {
						name:           "example2.com.",
						device:         "wg1",
						serveSelf:      true,
						selfEndpoint:   endpoint1,
						selfAllowedIPs: []net.IPNet{*prefix3, *prefix4},
					},
				},
				Names: []string{"example.com.", "example2.com."},
			},
		},
		{
			"all options",
			`wgsd example.com. wg0 {
						self 127.0.0.1:51820 1.1.1.1/32 2.2.2.2/32
					}`,
			false,
			Zones{
				Z: map[string]*Zone{
					"example.com.": {
						name:           "example.com.",
						device:         "wg0",
						serveSelf:      true,
						selfEndpoint:   endpoint1,
						selfAllowedIPs: []net.IPNet{*prefix1, *prefix2},
					},
				},
				Names: []string{"example.com."},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := caddy.NewTestController("dns", tc.input)
			zones, err := parse(c)

			if err == nil && tc.shouldErr {
				t.Fatal("expected errors, but got no error")
			} else if err != nil && !tc.shouldErr {
				t.Fatalf("expected no errors, but got '%v'", err)
			} else {
				if !reflect.DeepEqual(tc.expectedZones, zones) {
					t.Fatalf("expected %v, got %v", tc.expectedZones, zones)
				}
			}
		})
	}
}
