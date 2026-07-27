package ray2sing

import (
	"strings"

	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

func NaiveSingbox(vlessURL string) (*T.Outbound, error) {
	u, err := ParseUrl(vlessURL, 443)
	if err != nil {
		return nil, err
	}
	decoded := u.Params
	if decoded["security"] == "" {
		decoded["security"] = "tls"
	}

	// fmt.Printf("Port %v deco=%v", port, decoded)
	tlsOptions := getTLSOptions(decoded)
	stripNaiveUnsupportedTLSOptions(tlsOptions.TLS)
	uot := T.UDPOverTCPOptions{
		Enabled: getOneOfN(decoded, "", "uot") != "false" && getOneOfN(decoded, "", "uot") != "0",
	}

	return &T.Outbound{
		Tag:  u.Name,
		Type: C.TypeNaive,
		Options: &T.NaiveOutboundOptions{
			DialerOptions:               getDialerOptions(decoded),
			ServerOptions:               u.GetServerOption(),
			Username:                    u.Username,
			Password:                    u.Password,
			InsecureConcurrency:         toInt(getOneOfN(decoded, "0", "insecure_concurrency")),
			ExtraHeaders:                GetHttpHeaders(getOneOfN(decoded, "", "header")),
			QUIC:                        getOneOfN(decoded, "", "quic") != "",
			QUICCongestionControl:       getOneOfN(decoded, "", "quic_congestion_control"),
			OutboundTLSOptionsContainer: tlsOptions,
			UDPOverTCP:                  &uot,
		},
	}, nil
}

// stripNaiveUnsupportedTLSOptions clears every TLS field sing-box's naive outbound hard-rejects
// at build time (protocol/naive/outbound.go's NewOutbound: insecure, disable_sni, alpn, uTLS,
// reality, min/max_version, cipher_suites, curve_preferences, client_certificate/key, fragment,
// kernel TLS - naive is built on Chromium's cronet, which doesn't expose a way to honor most of
// these). getTLSOptions is shared across every protocol and has no naive-specific awareness, so
// it can set several of these from generic link params (e.g. allow_insecure=1, a manager-side
// default included on some naive links regardless of whether the server's cert is actually
// self-signed) - previously, passing any of them through made the outbound fail outright at
// CheckConfigOptions with a naive-specific error, even though most of these params being present
// says nothing about whether the connection would actually need them to work. Naive's own doc
// (via to_link's construction) never emits fp/alpn/reality/nosni itself, but generic subscription
// tooling reusing the same &fm=/&fp=-style query params elsewhere could still produce a link that
// sets one of these, so all of them are guarded here, not just the one this bug report hit.
func stripNaiveUnsupportedTLSOptions(tls *T.OutboundTLSOptions) {
	if tls == nil {
		return
	}
	tls.Insecure = false
	tls.DisableSNI = false
	tls.ALPN = nil
	tls.MinVersion = ""
	tls.MaxVersion = ""
	tls.CipherSuites = nil
	tls.CurvePreferences = nil
	tls.ClientCertificate = nil
	tls.ClientCertificatePath = ""
	tls.ClientKey = nil
	tls.ClientKeyPath = ""
	tls.Fragment = false
	tls.RecordFragment = false
	tls.KernelTx = false
	tls.KernelRx = false
	tls.UTLS = nil
	tls.Reality = nil
}

func GetHttpHeaders(header string) badoption.HTTPHeader {
	kvs := strings.Split(header, ",")
	res := badoption.HTTPHeader{}

	for _, raw := range kvs {
		splt := strings.SplitN(raw, ":", 2)
		if len(splt) != 2 {
			continue
		}
		k, v := splt[0], splt[1]
		if _, ok := res[k]; !ok {
			res[k] = []string{}
		}
		res[k] = append(res[k], v)
	}
	return res
}
