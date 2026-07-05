package ray2sing

import (
	"strconv"

	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
)

func WarpSingbox(url string) (*T.Endpoint, error) {
	u, err := ParseUrl(url, 0)
	if err != nil {
		return nil, err
	}
	getInt := func(key string) int {
		if v, ok := u.Params[key]; ok {
			i, _ := strconv.Atoi(v)
			return i
		}
		return 0
	}
	// fmt.Println(u.Username, "-", u.Password, "-", u.Params)
	// WireGuardWARPEndpointOptions (renamed from WARPEndpointOptions) no
	// longer has an AWG obfuscation sub-field in this pinned sing-box
	// version - jc/jmin/jmax/etc are dropped here rather than silently
	// applied nowhere; core WARP fields (server, identifier, noise, mtu)
	// are unaffected.
	_ = getInt
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
