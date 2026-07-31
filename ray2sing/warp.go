package ray2sing

import (
	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
)

// AmneziaWG obfuscation params (jc/jmin/jmax/s1-s4/h1-h4/i1-i5) have no home on
// WireGuardWARPEndpointOptions in this sing-box version - it dropped the AWG field entirely
// (WARP's *constant.WARPConfig only carries the Cloudflare-registration response shape, not
// AmneziaWG knobs). warp:// links silently drop jc/jmin/etc rather than erroring; revisit if/when
// sing-box reintroduces AWG obfuscation for WARP endpoints specifically.
func WarpSingbox(url string) (*T.Endpoint, error) {
	u, err := ParseUrl(url, 0)
	if err != nil {
		return nil, err
	}
	// fmt.Println(u.Username, "-", u.Password, "-", u.Params)
	out := T.Endpoint{
		Type: C.TypeWARP,
		Tag:  u.Name,
		Options: &T.WireGuardWARPEndpointOptions{
			ServerOptions: T.ServerOptions{
				Server:     u.Hostname,
				ServerPort: u.Port,
			},
			UniqueIdentifier: u.Username,
			Noise:            getWireGuardNoise(u.Params, false),
			MTU:              uint32(toInt(getOneOfN(u.Params, "1280", "mtu"))),
		},
	}

	if out.Tag == "" {
		out.Tag = "WARP"
	}
	return &out, nil
}
