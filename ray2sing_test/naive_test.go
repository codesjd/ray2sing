package ray2sing_test

import (
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
)

// TestNaiveLinkWithAllowInsecureDoesNotSetInsecure guards against a real bug: sing-box's naive
// outbound (built on Chromium's cronet, which has no way to disable TLS certificate validation)
// hard-rejects "insecure" at build time with "insecure is not supported on naive outbound" -
// confirmed against a real user's app.log ("ProfileFailure.unexpected... parse outbound[... Naive
// ...] error: insecure is not supported on naive outbound"). getTLSOptions is shared across every
// protocol and has no naive-specific awareness, so a naive link carrying the generic
// "allow_insecure=1" param (which hiddify-manager sets whenever a domain is in "Fake" mode or an
// admin explicitly opts in - it isn't naive-specific, so its presence doesn't necessarily mean
// this particular connection needs it) used to make every such naive link permanently unusable,
// rather than just proceeding with normal certificate validation.
func TestNaiveLinkWithAllowInsecureDoesNotSetInsecure(t *testing.T) {
	links := []string{
		`naive://ceebd7b9-2eb9-4482-ab06-50da7aaecf25:h@ir2.nekocafe.sbs:443/?security=tls&sni=ir2.nekocafe.sbs&uot=1&allow_insecure=1&header=hiddify-naive-secret:/F2ZXppquQKW0jWuRC9XumWJhxPN#ir2.nekocafe.sbs%20NaiveTLS`,
		`naive://ceebd7b9-2eb9-4482-ab06-50da7aaecf25:h@ir2.nekocafe.sbs:28788/?security=tls&sni=ir2.nekocafe.sbs&uot=1&allow_insecure=1&quic=1#ir2.nekocafe.sbs%20NaiveQuic`,
	}
	for _, link := range links {
		ctx := libbox.BaseContext(nil)
		opts, err := ray2sing.Ray2SingboxOptions(ctx, link, false)
		if err != nil {
			t.Fatalf("expected the naive link to convert, got error: %v", err)
		}
		if len(opts.Outbounds) != 1 || opts.Outbounds[0].Type != "naive" {
			t.Fatalf("expected 1 'naive'-type outbound, got %+v", opts.Outbounds)
		}
		naiveOpts, ok := opts.Outbounds[0].Options.(*option.NaiveOutboundOptions)
		if !ok || naiveOpts.TLS == nil {
			t.Fatalf("expected NaiveOutboundOptions with TLS, got %+v", opts.Outbounds[0].Options)
		}
		if naiveOpts.TLS.Insecure {
			t.Fatalf("expected allow_insecure=1 to be dropped for naive (unsupported, always a hard build error), got TLS.Insecure=true")
		}
	}
}

// TestNaiveLinkStripsAllUnsupportedTLSOptions is the broader guard: everything
// protocol/naive/outbound.go's NewOutbound checks and rejects (see its own comment block) must
// never reach a naive outbound's built config, regardless of which combination of link params
// produced it.
func TestNaiveLinkStripsAllUnsupportedTLSOptions(t *testing.T) {
	link := `naive://ceebd7b9-2eb9-4482-ab06-50da7aaecf25:h@ir2.nekocafe.sbs:443/?security=reality&sni=ir2.nekocafe.sbs&fp=chrome&alpn=h2,http/1.1&nosni=1&allow_insecure=1&pbk=abc&sid=1#test`

	ctx := libbox.BaseContext(nil)
	opts, err := ray2sing.Ray2SingboxOptions(ctx, link, false)
	if err != nil {
		t.Fatalf("expected the naive link to convert, got error: %v", err)
	}
	naiveOpts, ok := opts.Outbounds[0].Options.(*option.NaiveOutboundOptions)
	if !ok || naiveOpts.TLS == nil {
		t.Fatalf("expected NaiveOutboundOptions with TLS, got %+v", opts.Outbounds[0].Options)
	}
	tls := naiveOpts.TLS
	if tls.Insecure {
		t.Errorf("Insecure must be stripped")
	}
	if tls.DisableSNI {
		t.Errorf("DisableSNI must be stripped")
	}
	if len(tls.ALPN) > 0 {
		t.Errorf("ALPN must be stripped, got %v", tls.ALPN)
	}
	if tls.UTLS != nil {
		t.Errorf("UTLS must be stripped, got %+v", tls.UTLS)
	}
	if tls.Reality != nil {
		t.Errorf("Reality must be stripped, got %+v", tls.Reality)
	}
}
