package ray2sing_test

import (
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
	"github.com/sagernet/sing-box/experimental/libbox"
)

// Reported as "not recognized": vless:// links using KCP transport plus an "fm" (finalmask) param
// carrying xdns/xicmp settings. Two gaps compounded to break these:
//
//  1. getStreamSettingsXray had no "kcp" case at all - any type=kcp link failed immediately with
//     "unknown transport type: kcp", before the "fm" param was even looked at.
//  2. "fm" (a URL-encoded JSON blob for Xray-core's "finalmask" stream-settings field) was never
//     read anywhere.
//
// Separately, since neither KCP nor finalmask exist in sing-box's own protocol implementations at
// all (Xray-core-only features), such a link would also never reach the xray-core conversion path
// to begin with unless "use xray-core when possible" happened to be on - requiresXrayCore forces
// it for exactly this case, the same way an explicit "&core=xray" already did.
func TestXDNSLinkStartsRealXrayCoreInstance(t *testing.T) {
	link := `vless://6aca7d1d-632c-464f-b8de-f640962d89c7@8.8.8.8:53?type=kcp&headerType=none&security=none&fm=%7B%22udp%22%3A%5B%7B%22type%22%3A%22xdns%22%2C%22settings%22%3A%7B%22resolvers%22%3A%5B%22a.onionchips.sbs%2Budp%3A//8.8.8.8%3A53%22%2C%22a.onionchips.sbs%2Budp%3A//1.1.1.1%3A53%22%5D%7D%7D%5D%7D#a.onionchips.sbs%20XDNS`

	ctx := libbox.BaseContext(nil)
	opts, err := ray2sing.Ray2SingboxOptions(ctx, link, false)
	if err != nil {
		t.Fatalf("expected the xdns link to convert, got error: %v", err)
	}
	if len(opts.Outbounds) != 1 || opts.Outbounds[0].Type != "xray" {
		t.Fatalf("expected 1 'xray'-type outbound, got %+v", opts.Outbounds)
	}
	// CheckConfigOptions actually builds and starts an embedded Xray-core instance for this
	// outbound - the strongest available signal that "kcpSettings"/"finalmask" are wired
	// correctly and that the bundled Xray-core build genuinely understands the xdns transform.
	if err := libbox.CheckConfigOptions(opts); err != nil {
		t.Fatalf("real xray-core instance failed to start: %v", err)
	}
}

func TestXICMPLinkStartsRealXrayCoreInstance(t *testing.T) {
	link := `vless://6aca7d1d-632c-464f-b8de-f640962d89c7@104.238.173.131:5605?type=kcp&headerType=none&security=none&fm=%7B%22udp%22%3A%5B%7B%22type%22%3A%22xicmp%22%2C%22settings%22%3A%7B%22dgram%22%3Atrue%2C%22ips%22%3A%5B%5D%7D%7D%5D%7D#ns.onionchips.sbs%20XICMP`

	ctx := libbox.BaseContext(nil)
	opts, err := ray2sing.Ray2SingboxOptions(ctx, link, false)
	if err != nil {
		t.Fatalf("expected the xicmp link to convert, got error: %v", err)
	}
	if len(opts.Outbounds) != 1 || opts.Outbounds[0].Type != "xray" {
		t.Fatalf("expected 1 'xray'-type outbound, got %+v", opts.Outbounds)
	}
	if err := libbox.CheckConfigOptions(opts); err != nil {
		t.Fatalf("real xray-core instance failed to start: %v", err)
	}
}
