package ray2sing

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"runtime"

	"strconv"
	"strings"

	_ "github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

var configTypes = map[string]ParserFunc{
	"vmess://":     VmessSingbox,
	"vless://":     VlessSingbox,
	"trojan://":    TrojanSingbox,
	"svmess://":    VmessSingbox,
	"svless://":    VlessSingbox,
	"strojan://":   TrojanSingbox,
	"ss://":        ShadowsocksSingbox,
	"tuic://":      TuicSingbox,
	"hysteria://":  HysteriaSingbox,
	"hysteria2://": Hysteria2Singbox,
	"hy2://":       Hysteria2Singbox,
	"anytls://":    AnytlsSingbox,
	"ssh://":       SSHSingbox,
	"naive://":     NaiveSingbox,

	"ssconf://":  BeepassSingbox,
	"direct://":  DirectSingbox,
	"socks://":   SocksSingbox,
	"phttp://":   HttpSingbox,
	"phttps://":  HttpsSingbox,
	"http://":    HttpSingbox,
	"https://":   HttpsSingbox,
	"xvmess://":  VmessXray,
	"xvless://":  VlessXray,
	"xtrojan://": TrojanXray,
	"xdirect://": DirectXray,
	"mieru://":   MieruSingbox,
	"mierus://":  MieruSingbox,
	"psiphon://": PsiphonSingbox,
	"dnstt://":   DnsttSingbox,
}
var endpointParsers = map[string]EndpointParserFunc{
	"wg://":        AWGSingbox,
	"wireguard://": AWGSingbox,
	"warp://":      WarpSingbox,
	"awg://":       AWGSingbox,
	"[Interface]":  AWGSingboxTxt,
}
var xrayConfigTypes = map[string]ParserFunc{
	"vmess://":  VmessXray,
	"vless://":  VlessXray,
	"trojan://": TrojanXray,
	"direct://": DirectXray,
}

func decodeUrlBase64IfNeeded(config string) string {
	splt := strings.SplitN(config, "://", 2)
	if len(splt) < 2 {
		//return config
	}
	rest, _ := decodeBase64IfNeeded(splt[1])
	// fmt.Println(rest, err)
	return splt[0] + "://" + rest
}

type OutEnd struct {
	outbound *T.Outbound
	endpoint *T.Endpoint
}

// requiresXrayCore reports whether a link uses a feature that only exists via the embedded
// Xray-core engine - KCP transport and the "fm" (finalmask, e.g. xdns/xicmp) param, neither of
// which sing-box's native protocol implementations support at all - regardless of the
// "use xray-core when possible" setting. Without this, such a link would only ever be attempted
// through the native sing-box parser (which doesn't understand "type=kcp" or "fm=" either way)
// unless the user happened to have that setting on or the link carried an explicit "&core=xray".
func requiresXrayCore(config string) bool {
	u, err := url.Parse(config)
	if err != nil {
		return false
	}
	q := u.Query()
	// url.Query() is case-sensitive on both key and value; ParseUrl's own decoded map (used by
	// every other param lookup in this package) normalizes keys via normalizeStr, but re-parsing
	// here bypasses that - and even key case aside, the query *value* itself ("KCP" vs "kcp") was
	// never normalized anywhere, so a panel/link using different casing for either would silently
	// miss this gate and fall through to a native parser that can't handle KCP/finalmask at all.
	net := strings.ToLower(getFirstQueryValue(q, "net"))
	if net == "" {
		net = strings.ToLower(getFirstQueryValue(q, "type"))
	}
	return net == "kcp" || net == "mkcp" || getFirstQueryValue(q, "fm") != ""
}

// getFirstQueryValue looks up a query key case-insensitively (net.URL.Values is a case-sensitive
// map, so "Net"/"NET"/"net" are otherwise three different keys).
func getFirstQueryValue(q url.Values, key string) string {
	for k, v := range q {
		if strings.EqualFold(k, key) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

func processSingleConfig(config string, useXrayWhenPossible bool) (outend *OutEnd, err error) {
	defer func() {
		if r := recover(); r != nil {
			outend = nil
			stackTrace := make([]byte, 1024)
			s := runtime.Stack(stackTrace, false)
			stackStr := fmt.Sprint(string(stackTrace[:s]))
			err = E.New("Error in Parsing:", r, "Stack trace:", stackStr)
		}
	}()
	// configDecoded := decodeUrlBase64IfNeeded(config)
	outend = &OutEnd{}
	xrayRequired := requiresXrayCore(config)
	if useXrayWhenPossible || strings.Contains(config, "&core=xray") || xrayRequired {
		for k, v := range xrayConfigTypes {
			if strings.HasPrefix(config, k) {
				outend.outbound, err = v(config)
				break
			}
		}
		if err != nil && xrayRequired {
			// requiresXrayCore means this link uses a feature (KCP transport, "fm"/finalmask)
			// that doesn't exist in sing-box's native protocol implementations at all - falling
			// through to the native parser below on failure would silently replace the real
			// error (e.g. "invalid fm param") with a misleading, unrelated one from a parser
			// that was never going to understand this link either way (typically
			// "unknown transport type: kcp").
			return nil, err
		}
	}
	if outend.outbound == nil {
		for k, v := range configTypes {
			if strings.HasPrefix(config, k) {
				outend.outbound, err = v(config)
				break
			}
		}
		for k, v := range endpointParsers {
			if strings.HasPrefix(config, k) {
				outend.endpoint, err = v(config)
				break
			}
		}
	}

	if err != nil {
		return nil, err
	}
	if outend.endpoint == nil && outend.outbound == nil {
		return nil, E.New("Not supported config type")
	}
	if outend.outbound != nil && outend.outbound.Tag == "" {
		outend.outbound.Tag = outend.outbound.Type
	}
	if outend.endpoint != nil && outend.endpoint.Tag == "" {
		outend.endpoint.Tag = outend.endpoint.Type
	}

	// json.MarshalIndent(configSingbox, "", "  ")
	return outend, nil
}

func GenerateConfigLite(input string, useXrayWhenPossible bool) (*option.Options, error) {

	configArray := expandDecodedConfig(input)

	var outbounds []T.Outbound
	var endpoints []T.Endpoint
	counter := 0

	for _, config := range configArray {
		if len(config) < 5 || config[0] == '#' || config[0] == '/' {
			continue
		}
		detourTag := ""

		chains := strings.Split(config, " -> ")
		for i := len(chains) - 1; i >= 0; i-- {
			chain1 := chains[i]

			// fmt.Printf("%s", chain)
			chain, _ := decodeBase64IfNeeded(chain1)
			outend, err := processSingleConfig(chain, useXrayWhenPossible)

			if err != nil {
				fmt.Fprintf(os.Stderr, "Error in %s \n %v\n", config, err)

				continue
			}

			if outend.outbound != nil {
				outend.outbound.Tag += " § " + strconv.Itoa(counter)
				if dialerOpt, ok := outend.outbound.Options.(T.DialerOptionsWrapper); ok {
					d := dialerOpt.TakeDialerOptions()
					d.Detour = detourTag
					dialerOpt.ReplaceDialerOptions(d)
				}

				detourTag = outend.outbound.Tag
				outbounds = append(outbounds, *outend.outbound)

			} else if outend.endpoint != nil {
				outend.endpoint.Tag += " § " + strconv.Itoa(counter)
				if dialerOpt, ok := outend.endpoint.Options.(T.DialerOptionsWrapper); ok {
					d := dialerOpt.TakeDialerOptions()
					d.Detour = detourTag
					dialerOpt.ReplaceDialerOptions(d)
				}

				detourTag = outend.endpoint.Tag
				endpoints = append(endpoints, *outend.endpoint)

			}

			counter += 1

		}

	}

	if len(outbounds) == 0 && len(endpoints) == 0 {
		return nil, E.New("No outbounds found")
	}

	fullConfig := T.Options{
		Outbounds: outbounds,
		Endpoints: endpoints,
	}

	return &fullConfig, nil
}

func Ray2Singbox(ctx context.Context, configs string, useXrayWhenPossible bool) (out []byte, err error) {
	convertedData, err := Ray2SingboxOptions(ctx, configs, useXrayWhenPossible)
	if err != nil {
		return nil, err
	}
	// err = libbox.CheckConfigOptions(convertedData)
	// if err != nil {
	// 	return nil, err
	// }
	return convertedData.MarshalJSONContext(ctx)
}
func Ray2SingboxOptions(ctx context.Context, configs string, useXrayWhenPossible bool) (out *option.Options, err error) {
	defer func() {
		if r := recover(); r != nil {
			out = nil
			stackTrace := make([]byte, 1024)
			s := runtime.Stack(stackTrace, false)
			stackStr := fmt.Sprint(string(stackTrace[:s]))
			err = E.New("Error in Parsing", configs, r, "Stack trace:", stackStr)

		}
	}()

	configs, _ = decodeBase64IfNeeded(configs)

	convertedData, err := GenerateConfigLite(configs, useXrayWhenPossible)
	return convertedData, err
}
