package wgsd

import (
	"testing"

	"github.com/coredns/caddy"
)

func TestSetup(t *testing.T) {
	testCases := []struct {
		name      string
		input     string
		expectErr bool
	}{
		{
			"valid input b32",
			"wgsd example.com. wg0 b32",
			false,
		},
		{
			"valid input sha1",
			"wgsd example.com. wg0 sha1",
			false,
		},
		{
			"valid input hex",
			"wgsd example.com. wg0 hex",
			false,
		},
		{
			"valid input sha1 truncate",
			"wgsd example.com. wg0 sha1:7",
			false,
		},
		{
			"valid input hex truncate",
			"wgsd example.com. wg0 hex:7",
			false,
		},
		{
			"valid input hex truncate",
			"wgsd example.com. wg0 hex:-1",
			true,
		},
		{
			"invalid input b32 truncate",
			"wgsd example.com. wg0 b32:7",
			true,
		},
		{
			"missing token",
			"wgsd example.com.",
			true,
		},
		{
			"too many tokens",
			"wgsd example.com. wg0 b32 extra",
			true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := caddy.NewTestController("dns", tc.input)
			err := setup(c)
			if (err != nil) != tc.expectErr {
				t.Fatalf("expectErr: %v, got err=%v", tc.expectErr, err)
			}
		})
	}
}
