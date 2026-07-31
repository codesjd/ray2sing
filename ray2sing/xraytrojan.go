package ray2sing

import (
	T "github.com/sagernet/sing-box/option"
)

func TrojanXray(vlessURL string) (*T.Outbound, error) {
	u, err := ParseUrl(vlessURL, 443)
	if err != nil {
		return nil, err
	}
	decoded := u.Params
	// fmt.Printf("Port %v deco=%v", port, decoded)
	streamSettings, err := getStreamSettingsXray(decoded)
	if err != nil {
		return nil, err
	}

	// packetEncoding := decoded["packetencoding"]
	// if packetEncoding==""{
	// 	packetEncoding="xudp"
	// }
	res := map[string]any{

		"protocol": "trojan",

		"settings": map[string]any{
			"servers": []any{
				map[string]any{
					"address":  u.Hostname,
					"port":     u.Port,
					"password": u.Username,
				},
			},
		},
		"tag":            u.Name,
		"streamSettings": streamSettings,
	}
	if mux := getMuxOptionsXray(decoded); mux != nil {
		res["mux"] = mux
	}
	return makeXrayOptions(decoded, res)
}
