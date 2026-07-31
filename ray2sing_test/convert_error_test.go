package ray2sing_test

import (
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
	"github.com/sagernet/sing-box/experimental/libbox"
)

// Ray2Singbox used to discard the error from Ray2SingboxOptions and unconditionally
// MarshalJSONContext the (possibly nil) result, so no malformed input could ever surface an
// error through the public entry point even though the underlying parsers error correctly.
func TestRay2Singbox_MalformedVmess_ReturnsError(t *testing.T) {
	ctx := libbox.BaseContext(nil)

	_, err := ray2sing.Ray2Singbox(ctx, "vmess://not-valid-base64!!!", false)
	if err == nil {
		t.Fatal("expected Ray2Singbox to return an error for malformed vmess input, got nil")
	}
}

func TestRay2Singbox_MalformedTrojan_ReturnsError(t *testing.T) {
	ctx := libbox.BaseContext(nil)

	// Embedded control character - invalid in a URL.
	_, err := ray2sing.Ray2Singbox(ctx, "trojan://pass@host:443?sni=\x00#tag", false)
	if err == nil {
		t.Fatal("expected Ray2Singbox to return an error for malformed trojan input, got nil")
	}
}
