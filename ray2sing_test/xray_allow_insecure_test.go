package ray2sing_test

import (
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
)

// TestXrayLinkWithAllowInsecureDoesNotSetAllowInsecure guards against a real, currently-dated
// regression: real upstream xray-core permanently hard-rejects "allowInsecure": true as of
// 2026-06-01 (infra/conf/transport_internet.go's StreamConfig.Build():
// "if c.AllowInsecure { ... return nil, errors.PrintRemovedFeatureError(...) }", unconditional
// past that date, not just a warning) - confirmed against a real user's app.log ("The feature
// 'allowInsecure' has been removed and migrated to 'pinnedPeerCertSha256'"). getTLSOptionsXray
// used to set "allowInsecure": true unconditionally whenever a link asked for insecure fallback
// with no pcs= pin, making that outbound permanently fail to build - not just insecure, entirely
// unusable, on every single connection attempt.
func TestXrayLinkWithAllowInsecureDoesNotSetAllowInsecure(t *testing.T) {
	link := "vless://uuid-here@example.com:443?type=kcp&security=tls&sni=example.com&allow_insecure=1&core=xray"

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
	tlsSettings, _ := streamSettings["tlsSettings"].(map[string]any)
	if tlsSettings == nil {
		t.Fatalf("expected tlsSettings in the generated XConfig, got streamSettings: %+v", streamSettings)
	}
	if v, present := tlsSettings["allowInsecure"]; present && v == true {
		t.Fatalf(`expected "allowInsecure" to never be true (xray-core permanently rejects it) - got tlsSettings: %+v`, tlsSettings)
	}

	// The strongest available signal: a real embedded xray-core instance actually accepts this
	// config, rather than the outbound just having the right JSON shape (an earlier version of
	// this exact check would have "passed" against the shape alone while still hard-failing here).
	if err := libbox.CheckConfigOptions(opts); err != nil {
		t.Fatalf("real xray-core instance failed to start: %v", err)
	}
}
