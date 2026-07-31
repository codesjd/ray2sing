package ray2sing_test

import (
	"encoding/base64"
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
)

// xrayvmess.go used to parse the port via toInt16 (signed 16-bit) instead of vmess.go's
// toUInt16, so any vmess link with a server port above 32767 silently corrupted when routed
// through the xray backend (e.g. 51820 became -13716).
func TestXrayVmess_HighPort_NotTruncated(t *testing.T) {
	const vmessJSON = `{"add":"example.com","aid":"0","alpn":"","fp":"","host":"","id":"d43ee5e3-1b07-56d7-b2ea-8d22c44fdc66","net":"tcp","path":"","port":"51820","scy":"auto","sni":"","tls":"","type":"none","v":"2","ps":"xray-high-port-test"}`
	link := "vmess://" + base64.StdEncoding.EncodeToString([]byte(vmessJSON))

	ctx := libbox.BaseContext(nil)
	opts, err := ray2sing.Ray2SingboxOptions(ctx, link, true) // useXrayWhenPossible forces the xray backend
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
	settings, _ := (*xopts.XConfig)["settings"].(map[string]any)
	vnext, _ := settings["vnext"].([]any)
	if len(vnext) != 1 {
		t.Fatalf("expected 1 vnext entry, got %+v", settings["vnext"])
	}
	server, _ := vnext[0].(map[string]any)
	port, ok := server["port"].(uint16)
	if !ok {
		t.Fatalf("expected port to be a uint16, got %T (%v)", server["port"], server["port"])
	}
	if port != 51820 {
		t.Fatalf("expected port 51820, got %d (regression: signed int16 truncation)", port)
	}
}
