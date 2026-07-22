package ray2sing_test

import (
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
	T "github.com/sagernet/sing-box/option"
)

// TestXhttpNonH3KeepsUTLS guards against an operator-precedence bug in getTLSOptions: the
// condition `getALPNversion(...) == 3 && type == "xhttp" || net == "xhttp"` parses (per Go's
// standard && > || precedence) as `(ALPN==3 && type=="xhttp") || net=="xhttp"`, not the intended
// "only when ALPN is h3/QUIC, since XHTTP-over-H3 inherits a uTLS+QUIC bug". That meant ANY
// xhttp link with TLS unconditionally lost its uTLS fingerprint, even plain h1/h2 xhttp+TLS with
// no QUIC involved at all - a real, silent fingerprint downgrade that can trip server-side
// JA3/JA4 filtering. This link uses alpn=h2 (not h3), so uTLS must survive.
func TestXhttpNonH3KeepsUTLS(t *testing.T) {
	link := "vless://25da296e-1d96-48ae-9867-4342796cd742@example.com:443?encryption=none&fp=chrome&host=example.com&path=%2F&security=tls&sni=example.com&type=xhttp&alpn=h2"

	out, err := ray2sing.VlessSingbox(link)
	if err != nil {
		t.Fatalf("VlessSingbox: %v", err)
	}
	opts, ok := out.Options.(*T.VLESSOutboundOptions)
	if !ok {
		t.Fatalf("expected *option.VLESSOutboundOptions, got %T", out.Options)
	}
	if opts.TLS == nil {
		t.Fatalf("expected TLS to be enabled")
	}
	if opts.TLS.UTLS == nil || !opts.TLS.UTLS.Enabled || opts.TLS.UTLS.Fingerprint != "chrome" {
		t.Fatalf("expected uTLS fingerprint 'chrome' to survive for xhttp+alpn=h2 (non-QUIC), got %+v", opts.TLS.UTLS)
	}
}

// TestXhttpH3DropsUTLS is the companion case: xhttp actually negotiated over h3/QUIC (ALPN
// version 3) is exactly the scenario the original code meant to guard against (a known uTLS+QUIC
// bug), so UTLS should still be cleared there.
func TestXhttpH3DropsUTLS(t *testing.T) {
	link := "vless://25da296e-1d96-48ae-9867-4342796cd742@example.com:443?encryption=none&fp=chrome&host=example.com&path=%2F&security=tls&sni=example.com&type=xhttp&alpn=h3"

	out, err := ray2sing.VlessSingbox(link)
	if err != nil {
		t.Fatalf("VlessSingbox: %v", err)
	}
	opts, ok := out.Options.(*T.VLESSOutboundOptions)
	if !ok {
		t.Fatalf("expected *option.VLESSOutboundOptions, got %T", out.Options)
	}
	if opts.TLS == nil {
		t.Fatalf("expected TLS to be enabled")
	}
	if opts.TLS.UTLS != nil {
		t.Fatalf("expected uTLS to stay cleared for xhttp+alpn=h3 (QUIC), got %+v", opts.TLS.UTLS)
	}
}
