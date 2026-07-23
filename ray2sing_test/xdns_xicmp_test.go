package ray2sing_test

import (
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
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
//
// A third gap, found later: getFinalmask used to write the parsed "fm" object under a "finalmask"
// key wrapping {"udp": [...]}, neither of which exist in Xray-core's actual schema (the real field
// is a top-level "udpmasks" array - see getFinalmask's doc comment) - so the whole mask block was
// silently dropped on the JSON round-trip in xray/outbound.go's New(), and the outbound built and
// started as plain, unmasked KCP without error. Fixing that key mapping then exposed a fourth,
// deeper gap: the previously-vendored github.com/hiddify/xray-core was a single commit frozen
// since it was first pinned (no tags, no updates), whose mask-type registry never implemented
// "xdns"/"xicmp" at all - only "salamander" was ever registered there. This project now depends on
// real upstream github.com/xtls/xray-core directly (see go.mod), which has complete xdns/xicmp
// finalmask implementations - both tests below now build and start a real embedded instance
// successfully.
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
	// outbound - the strongest available signal that "kcpSettings"/"udpmasks" are wired
	// correctly and that the bundled Xray-core build genuinely understands the xdns transform.
	if err := libbox.CheckConfigOptions(opts); err != nil {
		t.Fatalf("real xray-core instance failed to start: %v", err)
	}
}

// TestMalformedFmFailsRatherThanSilentlyDroppingTheMask guards against getFinalmask silently
// swallowing a JSON parse error and returning an unmasked (but otherwise valid-looking) outbound.
// "fm" being present at all means the link specifically requires that mask - that's the entire
// point of an xdns/xicmp link - so a malformed value must fail the conversion instead of silently
// producing a plain KCP outbound that looks imported fine and then just doesn't behave as
// intended, with nothing indicating why.
func TestMalformedFmFailsRatherThanSilentlyDroppingTheMask(t *testing.T) {
	link := `vless://6aca7d1d-632c-464f-b8de-f640962d89c7@8.8.8.8:53?type=kcp&headerType=none&security=none&fm=not-valid-json#a.onionchips.sbs%20XDNS`

	ctx := libbox.BaseContext(nil)
	_, err := ray2sing.Ray2SingboxOptions(ctx, link, false)
	if err == nil {
		t.Fatalf("expected a malformed 'fm' param to fail the conversion instead of silently dropping the mask")
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

// TestRequiresXrayCoreIsCaseInsensitive guards against requiresXrayCore missing a KCP link because
// the query key or "type"/"net" value used different casing than the lowercase this package's own
// decoded map otherwise normalizes to everywhere else (see ParseUrl's normalizeStr) - re-parsing
// the URL independently here bypassed that entirely, on both key and value. A link that requires
// xray-core but whose gate misses it would fall through to a native parser that understands
// neither KCP nor finalmask at all, rather than the config actually being processed.
func TestRequiresXrayCoreIsCaseInsensitive(t *testing.T) {
	link := `vless://6aca7d1d-632c-464f-b8de-f640962d89c7@8.8.8.8:53?Type=KCP&headerType=none&security=none#uppercase-kcp-type`

	ctx := libbox.BaseContext(nil)
	opts, err := ray2sing.Ray2SingboxOptions(ctx, link, false)
	if err != nil {
		t.Fatalf("expected the link to convert, got error: %v", err)
	}
	if len(opts.Outbounds) != 1 || opts.Outbounds[0].Type != "xray" {
		t.Fatalf("expected uppercase 'Type=KCP' to still route through the embedded xray-core path, got %+v", opts.Outbounds)
	}
}

// TestKcpMtuParamReachesXConfig guards against getkcp() silently dropping mtu/tti/capacity params
// a link explicitly sets. hiddify-manager's generated xdns/xicmp links intentionally use a small
// mtu (tiny DNS-sized UDP payloads don't need a full-size KCP frame), so that value has to survive
// the link->outbound conversion to matter at all - xray/outbound.go's clampKcpMtu only ever gets a
// chance to adapt an out-of-range value if this puts one there in the first place. Below 576, the
// embedded engine's own clamp should still make it a working instance rather than a build failure.
func TestKcpMtuParamReachesXConfig(t *testing.T) {
	link := `vless://6aca7d1d-632c-464f-b8de-f640962d89c7@8.8.8.8:53?type=kcp&headerType=none&security=none&mtu=132&tti=20&uplinkCapacity=5&downlinkCapacity=20&congestion=false#a.onionchips.sbs%20XDNS`

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
	kcpSettings, _ := streamSettings["kcpSettings"].(map[string]any)
	if kcpSettings == nil {
		t.Fatalf("expected kcpSettings in the generated XConfig, got streamSettings: %+v", streamSettings)
	}
	if mtu, _ := kcpSettings["mtu"].(int); mtu != 132 {
		t.Fatalf("expected the link's mtu=132 to reach kcpSettings, got %+v", kcpSettings)
	}
	// The strongest available signal: a real embedded xray-core instance actually accepts the
	// below-576 mtu once clamped, rather than the outbound just having the right JSON shape.
	if err := libbox.CheckConfigOptions(opts); err != nil {
		t.Fatalf("real xray-core instance failed to start: %v", err)
	}
}
