package ray2sing_test

import (
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
)

// TestAwgLinkWithObfuscationParamsProducesAwgEndpoint guards the URL-form counterpart of the bug
// TestAmneziaConfTextParses covers for the .conf-text form: AWGSingbox had "if true || isAwg"
// (inverted polarity from AWGSingboxTxt's own copy of the same bug - here isAwg=true means real
// Jc/Jmin/etc params ARE present), which routed every wg://awg:// link through the plain
// WireGuard branch regardless, silently discarding Jc/Jmin/Jmax/H1-4/S1-4/I1-5 - a real Amnezia-WG
// server never negotiates plain WireGuard's handshake, so the connection failed outright.
func TestAwgLinkWithObfuscationParamsProducesAwgEndpoint(t *testing.T) {
	link := "awg://privkey123@example.com:51820/?peerpublickey=pubkey456&ip=10.0.0.2/24&jc=4&jmin=40&jmax=70&h1=1&h2=2&h3=3&h4=4&s1=74&s2=68&s3=50&s4=23"

	ctx := libbox.BaseContext(nil)
	opts, err := ray2sing.Ray2SingboxOptions(ctx, link, false)
	if err != nil {
		t.Fatalf("expected the awg link to convert, got error: %v", err)
	}
	if len(opts.Endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d: %+v", len(opts.Endpoints), opts.Endpoints)
	}
	if opts.Endpoints[0].Type != "awg" {
		t.Fatalf("expected an awg endpoint (real jc/jmin/etc params were set), got type %q", opts.Endpoints[0].Type)
	}
	awgOpts, ok := opts.Endpoints[0].Options.(*option.AwgEndpointOptions)
	if !ok {
		t.Fatalf("expected AwgEndpointOptions, got %T", opts.Endpoints[0].Options)
	}
	if awgOpts.Jc != 4 || awgOpts.Jmin != 40 || awgOpts.Jmax != 70 {
		t.Fatalf("expected Jc/Jmin/Jmax to reach AwgEndpointOptions, got Jc=%d Jmin=%d Jmax=%d", awgOpts.Jc, awgOpts.Jmin, awgOpts.Jmax)
	}
}

// TestPlainWireguardLinkStillProducesWireguardEndpoint guards the other side of the same
// condition: a link with no Jc/Jmin/etc obfuscation params at all must still produce a plain
// "wireguard" endpoint, not "awg" - flipping the polarity of the fix must not overshoot.
func TestPlainWireguardLinkStillProducesWireguardEndpoint(t *testing.T) {
	link := "wg://privkey123@example.com:51820/?peerpublickey=pubkey456&ip=10.0.0.2/24"

	ctx := libbox.BaseContext(nil)
	opts, err := ray2sing.Ray2SingboxOptions(ctx, link, false)
	if err != nil {
		t.Fatalf("expected the wg link to convert, got error: %v", err)
	}
	if len(opts.Endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d: %+v", len(opts.Endpoints), opts.Endpoints)
	}
	if opts.Endpoints[0].Type != "wireguard" {
		t.Fatalf("expected a plain wireguard endpoint (no obfuscation params set), got type %q", opts.Endpoints[0].Type)
	}
}
