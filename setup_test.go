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
			"valid input",
			"wgsd example.com. wg0",
			false,
		},
		{
			"missing token",
			"wgsd example.com.",
			true,
		},
		{
			"with local ip",
			"wgsd example.com. wg0 127.0.0.1",
			false,
		},
		{
			"too many tokens",
			"wgsd example.com. wg0 127.0.0.1 extra",
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
