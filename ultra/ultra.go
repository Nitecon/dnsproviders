// Package ultra adapts the lego UltraDNS
// provider for Caddy. Importing this package plugs it in.
package ultra

import (
	"errors"

	"github.com/mholt/caddy/caddytls"
	"github.com/xenolf/lego/acme"
	"github.com/xenolf/lego/providers/dns/ultra"
)

func init() {
	caddytls.RegisterDNSProvider("ultra", NewDNSProvider)
}

// NewDNSProvider returns a new UltraDNS DNS challenge provider.
// The credentials are interpreted as follows:
//
// len(0): use credentials from environment
// len(2): credentials[0] = Username
//         credentials[1] = Password
func NewDNSProvider(credentials ...string) (acme.ChallengeProvider, error) {
	switch len(credentials) {
	case 0:
		return ultra.NewDNSProvider()
	case 2:
		return ultra.NewDNSProviderCredentials(credentials[0], credentials[1])
	default:
		return nil, errors.New("invalid credentials length")
	}
}
