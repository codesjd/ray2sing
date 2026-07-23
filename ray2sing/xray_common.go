package ray2sing

import (
	"encoding/json"

	E "github.com/sagernet/sing/common/exceptions"
	// "github.com/xtls/xray-core/infra/conf"

	"strings"
)

// func marshalJSON(v interface{}) *json.RawMessage {
// 	data, _ := json.Marshal(v) // You should handle errors properly
// 	raw := json.RawMessage(data)
// 	return &raw
// }
// func getTLSOptionsXray(decoded map[string]string) *conf.TLSConfig {
// 	if !(decoded["tls"] == "tls" || decoded["security"] == "tls") {
// 		return nil
// 	}
// 	c := conf.TLSConfig{
// 		RejectUnknownSNI: false,
// 		Insecure:         decoded["insecure"] == "true" || decoded["insecure"] == "1",
// 		ServerName:       decoded["sni"],
// 		ALPN:             conf.NewStringList([]string{"h2", "http/1.1"}),
// 		Fingerprint:      decoded["fp"],
// 	}

// 	if c.ServerName == "" {
// 		c.ServerName = decoded["add"]
// 	}

// 	if alpnlink, ok := decoded["alpn"]; ok && alpnlink != "" {
// 		c.ALPN = conf.NewStringList(strings.Split(alpnlink, ","))
// 	}

// 	if c.Fingerprint == "" {
// 		// fp = "chrome"
// 	}

// 	return &c
// }
// func getRealityOptionsXray(decoded map[string]string) *conf.REALITYConfig {
// 	if !(decoded["security"] == "reality") {
// 		return nil
// 	}
// 	c := conf.REALITYConfig{
// 		ServerName:  decoded["sni"],
// 		Fingerprint: decoded["fp"],
// 		ShortId:     decoded["sid"],
// 		SpiderX:     decoded["spx"],
// 		PublicKey:   decoded["pbk"],
// 	}

// 	if c.ServerName == "" {
// 		c.ServerName = decoded["add"]
// 	}
// 	// alpn := []string{"h2", "http/1.1"}
// 	// if alpnlink, ok := decoded["alpn"]; ok && alpnlink != "" {
// 	// 	alpn = strings.Split(alpnlink, ",")
// 	// }

// 	if c.Fingerprint == "" {
// 		// fp = "chrome"
// 	}

// 	return &c
// }

// func getMuxOptionsXray(decoded map[string]string) *conf.MuxConfig {
// 	if decoded["mux"] == "" {
// 		return nil
// 	}
// 	return &conf.MuxConfig{
// 		Enabled:     true,
// 		Concurrency: toInt16(decoded["mux"], 0),

// 		// "xudpConcurrency": 16,
// 		// "xudpProxyUDP443": "reject"
// 	}
// }
// func getsplithttp(decoded map[string]string) *conf.SplitHTTPConfig {
// 	splt := conf.SplitHTTPConfig{
// 		Path: decoded["path"],
// 		Host: decoded["host"],
// 		Headers: map[string]string{
// 			"User-Agent": USER_AGENT,
// 		},
// 	}

// 	if splt.Path == "" {
// 		splt.Path = "/"
// 	}

// 	return &splt
// }
// func gethttpupgrade(decoded map[string]string) *conf.HttpUpgradeConfig {
// 	hc := conf.HttpUpgradeConfig{
// 		Path: decoded["path"],
// 		Host: decoded["host"],
// 		Headers: map[string]string{
// 			"User-Agent": USER_AGENT,
// 		},
// 	}

// 	if hc.Path == "" {
// 		hc.Path = "/"
// 	}

// 	return &hc
// }
// func getwebsocket(decoded map[string]string) *conf.WebSocketConfig {
// 	c := conf.WebSocketConfig{
// 		Path: decoded["path"],
// 		Host: decoded["host"],
// 		Headers: map[string]string{
// 			"User-Agent": USER_AGENT,
// 		},
// 	}

// 	if c.Path == "" {
// 		c.Path = "/"
// 	}

// 	return &c
// }

// // func geth2(decoded map[string]string) conf.{
// // 	path := decoded["path"]
// // 	if path == "" {
// // 		path = "/"
// // 	}

// // 	return map[string]any{
// // 		"path": path,
// // 		"host": strings.Split(decoded["host"], ","),
// // 		"headers": map[string]string{
// // 			"User-Agent": USER_AGENT,
// // 		},
// // 	}
// // }

// // func getquic(decoded map[string]string) map[string]any {

// // 	return map[string]any{
// // 		"security": decoded["quicSecurity"],
// // 		"key":      decoded["key"],
// // 		"header": map[string]string{
// // 			"type": decoded["headertype"],
// // 		},
// // 	}
// // }

// func getgrpc(decoded map[string]string) *conf.GRPCConfig {
// 	c := conf.GRPCConfig{
// 		Authority:   decoded["authority"],
// 		ServiceName: decoded["servicename"],
// 		MultiMode:   decoded["mode"] != "tun",
// 		UserAgent:   USER_AGENT,
// 	}
// 	return &c
// }

// func getStreamSettingsXray(decoded map[string]string) (*conf.StreamConfig, error) {

// 	net, path := decoded["net"], decoded["path"]
// 	if net == "" {
// 		net = decoded["type"]
// 	}
// 	if path == "" {
// 		path = decoded["servicename"]
// 	}
// 	// fmoption.Printf("\n\nheaderType:%s, net:%s, type:%s\n\n", decoded["headerType"], net, decoded["type"])
// 	// if (decoded["type"] == "http" || decoded["headertype"] == "http") && net == "tcp" {
// 	// 	net = "http"
// 	// }
// 	res := conf.StreamConfig{}
// 	if net == "splithttp" {
// 		net = "xhttp"
// 	}
// 	c := conf.TransportProtocol(net)
// 	res.Network = &c
// 	switch net {
// 	case "tcp":
// 		res.TCPSettings = &conf.TCPConfig{}
// 		decoded["alpn"] = "http/1.1"
// 	case "httpupgrade":

// 		res.HTTPUPGRADESettings = gethttpupgrade(decoded)
// 		decoded["alpn"] = "http/1.1"
// 	case "ws":
// 		res.WSSettings = getwebsocket(decoded)
// 		decoded["alpn"] = "http/1.1"
// 	case "grpc":
// 		res.GRPCSettings = getgrpc(decoded)
// 		decoded["alpn"] = "h2"
// 	// case "quic":
// 	// 	res[net+"Settings"] = getquic(decoded)
// 	// 	decoded["alpn"] = "h3"
// 	case "xhttp":
// 		res.SplitHTTPSettings = getsplithttp(decoded)
// 	case "splithttp":
// 		res.SplitHTTPSettings = getsplithttp(decoded)
// 	// case "h2":
// 	// 	res[net+"Settings"] = geth2(decoded)
// 	// 	decoded["alpn"] = "h2"
// 	default:
// 		return nil, E.New("unknown transport type: " + net)
// 	}
// 	res.TLSSettings = getTLSOptionsXray(decoded)
// 	if res.TLSSettings != nil {
// 		res.Security = "tls"
// 	}
// 	res.REALITYSettings = getRealityOptionsXray(decoded)
// 	if res.REALITYSettings != nil {
// 		res.Security = "reality"
// 	}
// 	return &res, nil
// }

// func getXrayFragmentOptions(decoded map[string]string) *conf.Fragment {
// 	trick := conf.Fragment{}
// 	fragment := decoded["fragment"]

// 	if fragment == "" {
// 		return &trick
// 	}
// 	splt := strings.Split(fragment, ",")

// 	if len(splt) > 2 {
// 		trick.Packets = splt[0]
// 		l, r, err := conf.ParseRangeString(splt[1])
// 		if err == nil {
// 			trick.Length = &conf.Int32Range{
// 				// From: int32(l),
// 				// To:   int32(r),
// 				Left:  int32(l),
// 				Right: int32(r),
// 			}
// 		}
// 		l, r, err = conf.ParseRangeString(splt[2])
// 		if err == nil {
// 			trick.Interval = &conf.Int32Range{
// 				// From: int32(l),
// 				// To:   int32(r),
// 				Left:  int32(l),
// 				Right: int32(r),
// 			}
// 		}

// 	}

// 	return &trick
// }

func getTLSOptionsXray(decoded map[string]string) map[string]any {
	if !(decoded["tls"] == "tls" || decoded["security"] == "tls") {
		return nil
	}
	serverName := decoded["sni"]
	if serverName == "" {
		serverName = decoded["add"]
	}
	alpn := []string{"h2", "http/1.1"}
	if alpnlink, ok := decoded["alpn"]; ok && alpnlink != "" {
		alpn = strings.Split(alpnlink, ",")
	}

	fp := decoded["fp"]
	if fp == "" {
		// fp = "chrome"
	}
	// xray-core's own JSON schema already has a pinnedPeerCertSha256 field (hex string) with
	// exactly the manager's pcs= semantics, so unlike the sing-box path this needs no separate
	// verification plumbing - just pass pcs straight through under xray-core's own field name.
	insecureFallback, pinnedCertSha256 := resolvePinnedCertOrInsecure(decoded)

	tlsSettings := map[string]any{
		"serverName":       serverName,
		"rejectUnknownSni": false,
		"allowInsecure":    insecureFallback,
		"alpn":             alpn,
		// "minVersion": "1.2",
		// "maxVersion": "1.3",
		// "disableSystemRoot": false,
		// "enableSessionResumption": true,
		"fingerprint": fp,
	}
	if len(pinnedCertSha256) > 0 {
		// xray-core's pinnedPeerCertSha256 accepts multiple hashes "~"-joined (see
		// infra/conf/transport_internet.go); join rather than taking just the first so a
		// future multi-pin pcs= (the manager only ever emits one today) round-trips correctly.
		tlsSettings["pinnedPeerCertSha256"] = strings.Join(pinnedCertSha256, "~")
	}
	return tlsSettings
}
func getRealityOptionsXray(decoded map[string]string) map[string]any {
	if !(decoded["security"] == "reality") {
		return nil
	}
	serverName := decoded["sni"]
	if serverName == "" {
		serverName = decoded["add"]
	}
	// alpn := []string{"h2", "http/1.1"}
	// if alpnlink, ok := decoded["alpn"]; ok && alpnlink != "" {
	// 	alpn = strings.Split(alpnlink, ",")
	// }

	fp := decoded["fp"]
	if fp == "" {
		// fp = "chrome"
	}

	return map[string]any{
		"serverName":  serverName,
		"fingerprint": fp,
		"shortId":     decoded["sid"],
		"spiderX":     decoded["spx"],
		"publicKey":   decoded["pbk"],
	}
}

func getMuxOptionsXray(decoded map[string]string) *map[string]any {
	if decoded["mux"] == "" {
		return nil
	}
	return &map[string]any{
		"enabled":     true,
		"concurrency": toInt(decoded["mux"]),
		// "xudpConcurrency": 16,
		// "xudpProxyUDP443": "reject"
	}
}
func getsplithttp(decoded map[string]string) map[string]any {
	path := decoded["path"]
	if path == "" {
		path = "/"
	}
	res := map[string]any{
		"path": path,
		"host": decoded["host"],

		// "headers": map[string]string{
		// 	"User-Agent": USER_AGENT,
		// }
	}
	if mode := decoded["mode"]; mode != "" {
		res["mode"] = decoded["mode"]
	}
	if extra, ok := decoded["extra"]; ok {

		var extraConfig map[string]any
		err := json.Unmarshal([]byte(extra), &extraConfig)
		if err != nil {
			return map[string]any{}
		}

		res["extra"] = extraConfig
	}

	return res

}
func convertJsonToRawMessage(v any) (json.RawMessage, error) {
	vBytes, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(vBytes), nil
}
func gethttpupgrade(decoded map[string]string) map[string]any {
	path := decoded["path"]
	if path == "" {
		path = "/"
	}

	return map[string]any{
		"path": path,
		"host": decoded["host"],
		// "headers": map[string]string{
		// 	"User-Agent": USER_AGENT,
		// },
	}
}
func getwebsocket(decoded map[string]string) map[string]any {
	path := decoded["path"]
	if path == "" {
		path = "/"
	}

	return map[string]any{
		"path": path,
		"host": decoded["host"],
		// "headers": map[string]string{
		// 	"User-Agent": USER_AGENT,
		// },
	}
}

func geth2(decoded map[string]string) map[string]any {
	path := decoded["path"]
	if path == "" {
		path = "/"
	}

	return map[string]any{
		"path": path,
		"host": strings.Split(decoded["host"], ","),
		// "headers": map[string]string{
		// 	"User-Agent": USER_AGENT,
		// },
	}
}

func getquic(decoded map[string]string) map[string]any {

	return map[string]any{
		"security": decoded["quicSecurity"],
		"key":      decoded["key"],
		"header": map[string]string{
			"type": decoded["headertype"],
		},
	}
}

func getgrpc(decoded map[string]string) map[string]any {

	return map[string]any{
		"authority":   decoded["authority"],
		"serviceName": decoded["servicename"],
		"mode":        decoded["mode"],
		// "user_agent":  USER_AGENT,
	}
}

func getStreamSettingsXray(decoded map[string]string) (map[string]any, error) {

	net, path := decoded["net"], decoded["path"]
	if net == "" {
		net = decoded["type"]
	}
	// ParseUrl's normalizeStr only lowercases query *keys*, not values, so a link using
	// "type=KCP"/"net=WS" etc reaches here with its original casing - the switch below matches
	// exact lowercase strings, so anything but all-lowercase would otherwise fail with a
	// confusing "unknown transport type" for a transport that's actually supported.
	net = strings.ToLower(net)
	if path == "" {
		path = decoded["servicename"]
	}
	// fmoption.Printf("\n\nheaderType:%s, net:%s, type:%s\n\n", decoded["headerType"], net, decoded["type"])
	// if (decoded["type"] == "http" || decoded["headertype"] == "http") && net == "tcp" {
	// 	net = "http"
	// }
	res := map[string]any{}
	if net == "splithttp" {
		net = "xhttp"
	}
	if net == "tcp" {
		net = "raw"
	}
	if net == "kcp" {
		net = "mkcp"
	}
	res["network"] = net
	switch net {
	case "mkcp":
		res["kcpSettings"] = getkcp(decoded)
	case "raw":
		res[net+"Settings"] = map[string]any{}
		decoded["alpn"] = "http/1.1"
	case "httpupgrade":
		res[net+"Settings"] = gethttpupgrade(decoded)
		decoded["alpn"] = "http/1.1"
	case "ws":
		res[net+"Settings"] = getwebsocket(decoded)
		decoded["alpn"] = "http/1.1"
	case "grpc":
		res[net+"Settings"] = getgrpc(decoded)
		decoded["alpn"] = "h2"
	case "quic":
		res[net+"Settings"] = getquic(decoded)
		decoded["alpn"] = "h3"
	case "xhttp":
		res[net+"Settings"] = getsplithttp(decoded)
		if _, ok := decoded["alpn"]; !ok {
			decoded["alpn"] = "h2"
		}
	case "h2":
		res[net+"Settings"] = geth2(decoded)
		decoded["alpn"] = "h2"
	default:
		return nil, E.New("unknown transport type: " + net)
	}
	tls := getTLSOptionsXray(decoded)
	if tls != nil {
		res["security"] = "tls"
		res["tlsSettings"] = tls
	}
	reality := getRealityOptionsXray(decoded)
	if reality != nil {
		res["security"] = "reality"
		res["realitySettings"] = reality
	}
	udpmasks, err := getFinalmask(decoded)
	if err != nil {
		return nil, err
	}
	if len(udpmasks) > 0 {
		res["udpmasks"] = udpmasks
	}
	return res, nil
}

// getkcp builds Xray-core's "kcpSettings" from the URI's "headerType"/"seed" params (transport
// type is "kcp" in the link, but "mkcp" in Xray-core's own JSON schema - see the network
// normalization above). "none" is the header-type default, so it's only set when overridden.
func getkcp(decoded map[string]string) map[string]any {
	kcp := map[string]any{}
	if headerType := decoded["headertype"]; headerType != "" && headerType != "none" {
		kcp["header"] = map[string]any{"type": headerType}
	}
	if seed := decoded["seed"]; seed != "" {
		kcp["seed"] = seed
	}
	// mtu/tti/capacity/buffer sizes: manager-generated xdns/xicmp links intentionally set a small
	// mtu (tiny DNS-sized UDP payloads don't need a full-size KCP frame), so these need to actually
	// reach xray-core's kcpSettings instead of being silently dropped - xray/outbound.go's
	// clampKcpMtu then adapts anything outside xray-core's own hard-enforced 576-1460 range rather
	// than letting the build fail.
	if mtu := toIntN(decoded["mtu"]); mtu != nil {
		kcp["mtu"] = *mtu
	}
	if tti := toIntN(decoded["tti"]); tti != nil {
		kcp["tti"] = *tti
	}
	if v := toIntN(decoded["uplinkcapacity"]); v != nil {
		kcp["uplinkCapacity"] = *v
	}
	if v := toIntN(decoded["downlinkcapacity"]); v != nil {
		kcp["downlinkCapacity"] = *v
	}
	if congestion, ok := decoded["congestion"]; ok {
		kcp["congestion"] = toBool(congestion, false)
	}
	if v := toIntN(decoded["readbuffersize"]); v != nil {
		kcp["readBufferSize"] = *v
	}
	if v := toIntN(decoded["writebuffersize"]); v != nil {
		kcp["writeBufferSize"] = *v
	}
	return kcp
}

// getFinalmask parses the "fm" URI param - a URL-encoded JSON object shaped
// {"udp":[{"type":"...","settings":{...}}, ...]} - into the array Xray-core's StreamConfig
// actually expects under its "udpmasks" field (infra/conf/transport_internet.go's
// `Udpmasks []*FinalMask `json:"udpmasks"``; each entry is `{Type string; Settings
// *json.RawMessage}`, matching the per-entry shape "fm" already uses). There is no top-level
// "finalmask" field in Xray-core's schema at all, and no wrapping "udp" key either - the field is
// the array itself. This function previously returned the raw parsed object as-is, which the
// caller then assigned to a "finalmask" key; since neither that key name nor the extra "udp"
// wrapping exist in Xray-core's JSON schema, the whole block was silently dropped on the
// json.Marshal/Unmarshal round-trip in xray/outbound.go's New() - the outbound built and started
// as plain KCP with no mask applied at all, rather than failing or actually masking anything.
//
// A malformed "fm" still fails the conversion rather than being dropped silently - "fm" being
// present at all means the link specifically requires that mask (that's the whole point of an
// xdns/xicmp link), so silently producing a plain, unmasked outbound instead would look like it
// imported fine and then just not behave as intended, with no indication why.
func getFinalmask(decoded map[string]string) ([]any, error) {
	fm := decoded["fm"]
	if fm == "" {
		return nil, nil
	}
	var parsed struct {
		UDP []any `json:"udp"`
	}
	if err := json.Unmarshal([]byte(fm), &parsed); err != nil {
		return nil, E.New("invalid fm (finalmask) param: " + err.Error())
	}
	return parsed.UDP, nil
}

// func getXrayFragmentOptions(decoded map[string]string) *conf.Fragment {
// 	fragment := decoded["fragment"]

// 	if fragment == "" {
// 		return nil
// 	}
// 	trick := conf.Fragment{}
// 	splt := strings.Split(fragment, ",")

// 	if len(splt) > 2 {
// 		trick.Packets = splt[0]
// 		l, r, err := conf.ParseRangeString(splt[1])
// 		if err == nil {
// 			trick.Length = &conf.Int32Range{
// 				// From: int32(l),
// 				// To:   int32(r),
// 				Left:  int32(l),
// 				Right: int32(r),
// 			}
// 		}
// 		l, r, err = conf.ParseRangeString(splt[2])
// 		if err == nil {
// 			trick.Interval = &conf.Int32Range{
// 				// From: int32(l),
// 				// To:   int32(r),
// 				Left:  int32(l),
// 				Right: int32(r),
// 			}
// 		}

// 	}

// 	return &trick
// }
