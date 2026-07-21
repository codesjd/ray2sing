package ray2sing_test

import (
	"reflect"
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
	T "github.com/sagernet/sing-box/option"
)

// tlsOptionsOf extracts the OutboundTLSOptions embedded in a parsed outbound's Options, for the
// protocol-specific option types that carry one (all four exercised below).
func tlsOptionsOf(t *testing.T, outboundOptions any) *T.OutboundTLSOptions {
	t.Helper()
	switch opts := outboundOptions.(type) {
	case *T.VLESSOutboundOptions:
		return opts.OutboundTLSOptionsContainer.TLS
	case *T.TrojanOutboundOptions:
		return opts.OutboundTLSOptionsContainer.TLS
	case *T.TUICOutboundOptions:
		return opts.OutboundTLSOptionsContainer.TLS
	case *T.Hysteria2OutboundOptions:
		return opts.OutboundTLSOptionsContainer.TLS
	case *T.AnyTLSOutboundOptions:
		return opts.OutboundTLSOptionsContainer.TLS
	default:
		t.Fatalf("unsupported outbound options type %T", outboundOptions)
		return nil
	}
}

// --- AnyTLS link parsing ---

func TestAnytlsBasic(t *testing.T) {
	out, err := ray2sing.AnytlsSingbox("anytls://8e0f4d1c-uuid@example.com:443?sni=s.example.com&alpn=h2,http/1.1&fp=chrome")
	if err != nil {
		t.Fatalf("AnytlsSingbox: %v", err)
	}
	if out.Type != "anytls" {
		t.Fatalf("Type = %q, want anytls", out.Type)
	}
	opts, ok := out.Options.(*T.AnyTLSOutboundOptions)
	if !ok {
		t.Fatalf("Options type = %T, want *T.AnyTLSOutboundOptions", out.Options)
	}
	if opts.Password != "8e0f4d1c-uuid" {
		t.Errorf("Password = %q, want the bare uuid", opts.Password)
	}
	if opts.Server != "example.com" || opts.ServerPort != 443 {
		t.Errorf("ServerOptions = %s:%d, want example.com:443", opts.Server, opts.ServerPort)
	}
	tls := opts.OutboundTLSOptionsContainer.TLS
	if tls == nil || !tls.Enabled {
		t.Fatalf("TLS not enabled, got %+v", tls)
	}
	if tls.ServerName != "s.example.com" {
		t.Errorf("ServerName = %q, want s.example.com", tls.ServerName)
	}
	if !reflect.DeepEqual([]string(tls.ALPN), []string{"h2", "http/1.1"}) {
		t.Errorf("ALPN = %v, want [h2 http/1.1]", tls.ALPN)
	}
	if tls.UTLS == nil || tls.UTLS.Fingerprint != "chrome" {
		t.Errorf("UTLS fingerprint = %+v, want chrome", tls.UTLS)
	}
	if tls.Insecure {
		t.Error("Insecure = true, want false (no insecure/pcs param given)")
	}
	if len(tls.PinnedPeerCertificateSha256) != 0 {
		t.Errorf("PinnedPeerCertificateSha256 = %v, want empty", tls.PinnedPeerCertificateSha256)
	}
}

func TestAnytlsInsecureFallback(t *testing.T) {
	out, err := ray2sing.AnytlsSingbox("anytls://uuid@example.com:443?sni=s.example.com&alpn=h2&insecure=1&allow_insecure=1")
	if err != nil {
		t.Fatalf("AnytlsSingbox: %v", err)
	}
	tls := tlsOptionsOf(t, out.Options)
	if !tls.Insecure {
		t.Error("Insecure = false, want true")
	}
	if len(tls.PinnedPeerCertificateSha256) != 0 {
		t.Errorf("PinnedPeerCertificateSha256 = %v, want empty when falling back to insecure", tls.PinnedPeerCertificateSha256)
	}
}

// --- pcs= pinned-certificate parsing, across link forms ---

const testPin = "a3f5b2c1d4e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7081920a1b2c3d4e5f6"

func TestPcsGenericVless(t *testing.T) {
	out, err := ray2sing.VlessSingbox("vless://uuid-here@example.com:443?security=tls&sni=s.example.com&pcs=" + testPin)
	if err != nil {
		t.Fatalf("VlessSingbox: %v", err)
	}
	tls := tlsOptionsOf(t, out.Options)
	assertPinned(t, tls, testPin)
}

func TestPcsTrojan(t *testing.T) {
	out, err := ray2sing.TrojanSingbox("trojan://password@example.com:443?security=tls&sni=s.example.com&pcs=" + testPin)
	if err != nil {
		t.Fatalf("TrojanSingbox: %v", err)
	}
	tls := tlsOptionsOf(t, out.Options)
	assertPinned(t, tls, testPin)
}

func TestPcsTuic(t *testing.T) {
	out, err := ray2sing.TuicSingbox("tuic://uuid:uuid@example.com:443?congestion_control=bbr&sni=s.example.com&pcs=" + testPin)
	if err != nil {
		t.Fatalf("TuicSingbox: %v", err)
	}
	tls := tlsOptionsOf(t, out.Options)
	assertPinned(t, tls, testPin)
}

func TestPcsHysteria2(t *testing.T) {
	out, err := ray2sing.Hysteria2Singbox("hysteria2://password@example.com:443?sni=s.example.com&pcs=" + testPin)
	if err != nil {
		t.Fatalf("Hysteria2Singbox: %v", err)
	}
	tls := tlsOptionsOf(t, out.Options)
	assertPinned(t, tls, testPin)
}

func TestPcsAnytls(t *testing.T) {
	out, err := ray2sing.AnytlsSingbox("anytls://uuid@example.com:443?sni=s.example.com&alpn=h2&pcs=" + testPin)
	if err != nil {
		t.Fatalf("AnytlsSingbox: %v", err)
	}
	tls := tlsOptionsOf(t, out.Options)
	assertPinned(t, tls, testPin)
}

func assertPinned(t *testing.T, tls *T.OutboundTLSOptions, wantHex string) {
	t.Helper()
	if tls == nil {
		t.Fatal("TLS options is nil")
	}
	if tls.Insecure {
		t.Error("Insecure = true, want false when a pin is present (pcs and insecure are mutually exclusive)")
	}
	if !reflect.DeepEqual([]string(tls.PinnedPeerCertificateSha256), []string{wantHex}) {
		t.Errorf("PinnedPeerCertificateSha256 = %v, want [%s]", tls.PinnedPeerCertificateSha256, wantHex)
	}
}

var testPin2 = "1122334455667788112233445566778811223344556677881122334455667788"[:64]

func TestPcsMultiPin(t *testing.T) {
	out, err := ray2sing.VlessSingbox("vless://uuid-here@example.com:443?security=tls&sni=s.example.com&pcs=" + testPin + "~" + testPin2)
	if err != nil {
		t.Fatalf("VlessSingbox: %v", err)
	}
	tls := tlsOptionsOf(t, out.Options)
	if tls.Insecure {
		t.Error("Insecure = true, want false")
	}
	if !reflect.DeepEqual([]string(tls.PinnedPeerCertificateSha256), []string{testPin, testPin2}) {
		t.Errorf("PinnedPeerCertificateSha256 = %v, want [%s %s]", tls.PinnedPeerCertificateSha256, testPin, testPin2)
	}
}

func TestPcsMalformedEntryDropped(t *testing.T) {
	// One malformed entry alongside a valid one: the valid pin still applies, malformed is
	// dropped (not passed through to fail confusingly at the TLS layer).
	out, err := ray2sing.VlessSingbox("vless://uuid-here@example.com:443?security=tls&sni=s.example.com&pcs=not-hex~" + testPin)
	if err != nil {
		t.Fatalf("VlessSingbox: %v", err)
	}
	tls := tlsOptionsOf(t, out.Options)
	if !reflect.DeepEqual([]string(tls.PinnedPeerCertificateSha256), []string{testPin}) {
		t.Errorf("PinnedPeerCertificateSha256 = %v, want [%s] (malformed entry dropped)", tls.PinnedPeerCertificateSha256, testPin)
	}
}

func TestPcsAllMalformedFailsClosed(t *testing.T) {
	// Every pcs entry malformed, no insecure fallback given: must NOT silently become insecure -
	// empty pin list, normal certificate validation applies (fails closed).
	out, err := ray2sing.VlessSingbox("vless://uuid-here@example.com:443?security=tls&sni=s.example.com&pcs=not-hex")
	if err != nil {
		t.Fatalf("VlessSingbox: %v", err)
	}
	tls := tlsOptionsOf(t, out.Options)
	if tls.Insecure {
		t.Error("Insecure = true, want false: an all-malformed pcs must not silently downgrade to insecure")
	}
	if len(tls.PinnedPeerCertificateSha256) != 0 {
		t.Errorf("PinnedPeerCertificateSha256 = %v, want empty", tls.PinnedPeerCertificateSha256)
	}
}

// TestInsecureFallbackCasingVariants guards resolvePinnedCertOrInsecure's cleanKey/getAny
// normalization: the manager emits the same fallback flag as "allowInsecure" (vmess JSON),
// "allow_insecure" (tuic/anytls/hysteria2 query params - which ParseUrl's normalizeStr turns into
// "allow insecure"), and plain "insecure" - all of which must be recognized identically.
func TestInsecureFallbackCasingVariants(t *testing.T) {
	cases := []string{
		"tuic://uuid:uuid@example.com:443?congestion_control=bbr&sni=s.example.com&allow_insecure=1",
		"hysteria2://password@example.com:443?sni=s.example.com&insecure=1",
		"anytls://uuid@example.com:443?sni=s.example.com&alpn=h2&insecure=1&allow_insecure=1",
	}
	for _, link := range cases {
		var tls *T.OutboundTLSOptions
		var err error
		switch {
		case len(link) > 5 && link[:5] == "tuic:":
			var out *T.Outbound
			out, err = ray2sing.TuicSingbox(link)
			if out != nil {
				tls = tlsOptionsOf(t, out.Options)
			}
		case len(link) > 10 && link[:10] == "hysteria2:":
			var out *T.Outbound
			out, err = ray2sing.Hysteria2Singbox(link)
			if out != nil {
				tls = tlsOptionsOf(t, out.Options)
			}
		default:
			var out *T.Outbound
			out, err = ray2sing.AnytlsSingbox(link)
			if out != nil {
				tls = tlsOptionsOf(t, out.Options)
			}
		}
		if err != nil {
			t.Fatalf("%s: %v", link, err)
		}
		if !tls.Insecure {
			t.Errorf("%s: Insecure = false, want true", link)
		}
	}
}

// --- Xray-core engine routing gate ---

func TestXrayRoutingGate(t *testing.T) {
	link := "vless://uuid-here@example.com:443?security=tls&sni=s.example.com&type=ws&path=/ws"

	// useXrayWhenPossible=false, no &core=xray hint: routes through the sing-box parser.
	opts, err := ray2sing.GenerateConfigLite(link, false)
	if err != nil {
		t.Fatalf("GenerateConfigLite(false): %v", err)
	}
	if len(opts.Outbounds) != 1 {
		t.Fatalf("got %d outbounds, want 1", len(opts.Outbounds))
	}
	if opts.Outbounds[0].Type != "vless" {
		t.Errorf("useXrayWhenPossible=false: outbound type = %q, want vless (sing-box path)", opts.Outbounds[0].Type)
	}

	// useXrayWhenPossible=true: routes through the xray-core parser instead.
	opts, err = ray2sing.GenerateConfigLite(link, true)
	if err != nil {
		t.Fatalf("GenerateConfigLite(true): %v", err)
	}
	if len(opts.Outbounds) != 1 {
		t.Fatalf("got %d outbounds, want 1", len(opts.Outbounds))
	}
	if opts.Outbounds[0].Type != "xray" {
		t.Errorf("useXrayWhenPossible=true: outbound type = %q, want xray", opts.Outbounds[0].Type)
	}

	// &core=xray forces the xray path even with useXrayWhenPossible=false.
	opts, err = ray2sing.GenerateConfigLite(link+"&core=xray", false)
	if err != nil {
		t.Fatalf("GenerateConfigLite with &core=xray: %v", err)
	}
	if len(opts.Outbounds) != 1 {
		t.Fatalf("got %d outbounds, want 1", len(opts.Outbounds))
	}
	if opts.Outbounds[0].Type != "xray" {
		t.Errorf("&core=xray hint: outbound type = %q, want xray", opts.Outbounds[0].Type)
	}

	// A protocol the xray path doesn't cover (tuic) still falls back to sing-box even with
	// useXrayWhenPossible=true.
	opts, err = ray2sing.GenerateConfigLite("tuic://uuid:uuid@example.com:443?congestion_control=bbr&sni=s.example.com", true)
	if err != nil {
		t.Fatalf("GenerateConfigLite(tuic, true): %v", err)
	}
	if len(opts.Outbounds) != 1 {
		t.Fatalf("got %d outbounds, want 1", len(opts.Outbounds))
	}
	if opts.Outbounds[0].Type != "tuic" {
		t.Errorf("tuic with useXrayWhenPossible=true: outbound type = %q, want tuic (no xray parser for tuic)", opts.Outbounds[0].Type)
	}
}
