package wgsd

import (
	"testing"

	"github.com/coredns/caddy"
)

func TestSetup(t *testing.T) {
	testCases := []struct {
		name                 string
		input                string
		expectErr            bool
		expectSelfAllowedIPs []string
		expectSelfEndpoint   []string
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
			nil,
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
			nil,
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
			nil,
			nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := caddy.NewTestController("dns", tc.input)
			err := setup(c)
			if (err != nil) != tc.expectErr {
				t.Fatalf("expectErr: %v, got err=%v", tc.expectErr, err)
			}
			if tc.expectErr {
				return
			}
		})
	}
}
