package ray2sing

import (
	"strings"

	T "github.com/sagernet/sing-box/option"
)

// AnytlsSingbox parses the manager's anytls:// link format:
//
//	anytls://<uuid>@<host>:<port>?sni=<sni>&alpn=<alpn>[&fp=<fingerprint>][&pcs=<hex sha256>|&insecure=1&allow_insecure=1]
//
// AnyTLS auth is a bare password (the uuid); the manager never sets a separate password field for
// this proto, matching Hiddify Manager's xray.py to_link() anytls branch.
func AnytlsSingbox(anytlsURL string) (*T.Outbound, error) {
	u, err := ParseUrl(anytlsURL, 443)
	if err != nil {
		return nil, err
	}
	decoded := u.Params

	serverName := decoded["sni"]
	if serverName == "" {
		serverName = u.Hostname
	}

	insecureFallback, pinnedCertSha256 := resolvePinnedCertOrInsecure(decoded)
	tlsOptions := &T.OutboundTLSOptions{
		Enabled:                     true,
		ServerName:                  serverName,
		Insecure:                    insecureFallback,
		PinnedPeerCertificateSha256: pinnedCertSha256,
	}
	if alpn, ok := decoded["alpn"]; ok && alpn != "" {
		tlsOptions.ALPN = strings.Split(alpn, ",")
	}
	if fp := decoded["fp"]; fp != "" {
		tlsOptions.UTLS = &T.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: fp,
		}
	}

	return &T.Outbound{
		Type: "anytls",
		Tag:  u.Name,
		Options: &T.AnyTLSOutboundOptions{
			DialerOptions: getDialerOptions(decoded),
			ServerOptions: u.GetServerOption(),
			Password:      u.Username,
			OutboundTLSOptionsContainer: T.OutboundTLSOptionsContainer{
				TLS: tlsOptions,
			},
		},
	}, nil
}
