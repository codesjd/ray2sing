package ray2sing_test

import (
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
	"github.com/sagernet/sing-box/experimental/libbox"
)

// Reported as "not working, even though the exact same configuration works fine in the official
// Amnezia client": a wg-quick/AmneziaWG ".conf" text block (as opposed to the wg:// link form,
// which already worked). Two real bugs compounded to break this:
//
//  1. expandDecodedConfig's line-splitter creates a new chunk at every line starting with "#" (so
//     that a genuine "# label" comment ahead of the next real link doesn't get glued onto it) - but
//     wg-quick/.conf files conventionally have their own "# Name = ..." comment lines *inside* the
//     [Interface]/[Peer] block, which were shredding the block down to just its "[Interface]"
//     header before it ever reached the parser.
//  2. AWGSingboxTxt's "AllowedIPs" field only parsed a single CIDR, not the "0.0.0.0/0, ::/0"
//     comma-separated form actually used here (unlike "Address" right above it in the same
//     function, which already split on commas).
func TestAmneziaConfTextParses(t *testing.T) {
	conf := `#=========104.238.173.131 AmneziaWG================
[Interface]
# Name = 104.238.173.131 AmneziaWG
Address= 10.91.0.2/32, fd42:42:91::2/128
PrivateKey = UJDnprEya1+nT6iR2uBXgVyR7xq0p6II5i9LYz9aE2c=
MTU = 1380
DNS = 1.1.1.1
Jc = 4
Jmin = 40
Jmax = 70
H1 = 1
H2 = 2
H3 = 3
H4 = 4
S1 = 74
S2 = 68
S3 = 50
S4 = 23

[Peer]
# Name = Public Peer for 104.238.173.131 AmneziaWG
Endpoint = 104.238.173.131:18619
PublicKey = 9+Mr5nGYMoM/6E8s2HXYNr5j3uUY2I8Nz/+/DiQLiFk=
PresharedKey = tZNgLU1XkVRufwxnsZ+bXcKsqzWpJEpbFauVb3Ifh34=
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`

	ctx := libbox.BaseContext(nil)
	opts, err := ray2sing.Ray2SingboxOptions(ctx, conf, false)
	if err != nil {
		t.Fatalf("expected the AmneziaWG .conf block to parse, got error: %v", err)
	}
	if len(opts.Endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d: %+v", len(opts.Endpoints), opts.Endpoints)
	}
	if opts.Endpoints[0].Type != "wireguard" {
		t.Fatalf("expected a wireguard endpoint, got type %q", opts.Endpoints[0].Type)
	}
}

// A "[Interface]" block must only absorb its own comment/continuation lines, not swallow whatever
// real link happens to follow it in the same subscription.
func TestAmneziaConfTextDoesNotSwallowFollowingLink(t *testing.T) {
	content := `#=========104.238.173.131 AmneziaWG================
[Interface]
# Name = 104.238.173.131 AmneziaWG
Address = 10.91.0.2/32
PrivateKey = UJDnprEya1+nT6iR2uBXgVyR7xq0p6II5i9LYz9aE2c=

[Peer]
Endpoint = 104.238.173.131:18619
PublicKey = 9+Mr5nGYMoM/6E8s2HXYNr5j3uUY2I8Nz/+/DiQLiFk=
AllowedIPs = 0.0.0.0/0, ::/0

# a second, unrelated server
vless://6aca7d1d-632c-464f-b8de-f640962d89c7@104.238.173.131:5605?type=tcp&security=none#second
`

	ctx := libbox.BaseContext(nil)
	opts, err := ray2sing.Ray2SingboxOptions(ctx, content, false)
	if err != nil {
		t.Fatalf("expected both entries to parse, got error: %v", err)
	}
	if len(opts.Endpoints) != 1 {
		t.Fatalf("expected 1 endpoint (the AmneziaWG block), got %d", len(opts.Endpoints))
	}
	if len(opts.Outbounds) != 1 {
		t.Fatalf("expected 1 outbound (the trailing vless link), got %d: %+v", len(opts.Outbounds), opts.Outbounds)
	}
}
