package ray2sing

import (
	T "github.com/sagernet/sing-box/option"
)

// AnyTLS is always TLS-terminated (there is no plaintext variant), so
// default security to "tls" the same way naive.go does, rather than
// requiring every link producer to remember the query param.
func AnyTLSSingbox(anytlsURL string) (*T.Outbound, error) {
	u, err := ParseUrl(anytlsURL, 443)
	if err != nil {
		return nil, err
	}
	decoded := u.Params
	if decoded["security"] == "" && decoded["tls"] == "" {
		decoded["security"] = "tls"
	}

	return &T.Outbound{
		Tag:  u.Name,
		Type: "anytls",
		Options: &T.AnyTLSOutboundOptions{
			DialerOptions:               getDialerOptions(decoded),
			ServerOptions:               u.GetServerOption(),
			Password:                    u.Username,
			OutboundTLSOptionsContainer: getTLSOptions(decoded),
		},
	}, nil
}
