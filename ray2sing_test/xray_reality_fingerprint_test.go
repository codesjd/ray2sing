package ray2sing_test

import (
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
)

// TestXrayRealityDefaultsFingerprintToChrome guards against a fixed divergence between backends:
// for a VLESS/Reality link with no fp= parameter, the sing-box path (getTLSOptions in common.go)
// has always defaulted the uTLS fingerprint to "chrome" for reality, but getRealityOptionsXray
// (the xray-core path) left it commented out and passed an empty fingerprint straight through.
// An empty fingerprint changes the TLS ClientHello shape, which is exactly what reality's
// anti-fingerprinting design depends on being consistent and browser-like - see
// plans/035-unify-tls-fingerprint-defaults.md.
func TestXrayRealityDefaultsFingerprintToChrome(t *testing.T) {
	link := "vless://uuid-here@example.com:443?type=tcp&security=reality&sni=example.com&pbk=pubkey&sid=1&core=xray"

	ctx := libbox.BaseContext(nil)
	opts, err := ray2sing.Ray2SingboxOptions(ctx, link, false)
	if err != nil {
		t.Fatalf("expected the link to convert, got error: %v", err)
	}
	if len(opts.Outbounds) != 1 || opts.Outbounds[0].Type != "xray" {
		t.Fatalf("expected 1 'xray'-type outbound, got %+v", opts.Outbounds)
	}
	xopts, ok := opts.Outbounds[0].Options.(*option.XrayOutboundOptions)
	if !ok || xopts.XConfig == nil {
		t.Fatalf("expected XrayOutboundOptions with XConfig, got %+v", opts.Outbounds[0].Options)
	}
	streamSettings, _ := (*xopts.XConfig)["streamSettings"].(map[string]any)
	realitySettings, _ := streamSettings["realitySettings"].(map[string]any)
	if realitySettings == nil {
		t.Fatalf("expected realitySettings in the generated XConfig, got streamSettings: %+v", streamSettings)
	}
	if fp, _ := realitySettings["fingerprint"].(string); fp != "chrome" {
		t.Fatalf(`expected realitySettings.fingerprint to default to "chrome" when fp= is unset, got: %+v`, realitySettings)
	}
}
