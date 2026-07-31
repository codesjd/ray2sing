package ray2sing

import (
	T "github.com/sagernet/sing-box/option"
)

func VlessXray(vlessURL string) (*T.Outbound, error) {
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
	user := map[string]string{
		"id":         u.Username,
		"encryption": "none",
	}
	if flow := decoded["flow"]; flow != "" {
		user["flow"] = flow
	}

	res := map[string]any{

		"protocol": "vless",
		"settings": map[string]any{
			"vnext": []any{
				map[string]any{
					"address": u.Hostname,
					"port":    u.Port,
					"users": []any{
						user,
					},
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
