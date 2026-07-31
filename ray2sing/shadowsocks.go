package ray2sing

import (
	"fmt"

	T "github.com/sagernet/sing-box/option"
)

func ShadowsocksSingbox(shadowsocksUrl string) (*T.Outbound, error) {
	u, err := ParseUrl(shadowsocksUrl, 443)
	if err != nil {
		return nil, err
	}

	if u.Password == "" {
		return nil, fmt.Errorf("shadowsocks: link missing password (malformed or unsupported userinfo encoding)")
	}

	decoded := u.Params

	result := T.Outbound{
		Type: "shadowsocks",
		Tag:  u.Name,
		Options: &T.ShadowsocksOutboundOptions{
			ServerOptions: u.GetServerOption(),
			Method:        u.Username,
			Password:      u.Password,
			Plugin:        decoded["plugin"],
			PluginOptions: decoded["pluginopts"],
		},
	}

	return &result, nil
}
