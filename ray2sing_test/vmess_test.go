package ray2sing_test

import (
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
)

func TestVmess(t *testing.T) {

	url := "vmess://eyJhZGQiOiI1MS4xNjEuMTMwLjE3MyIsImFpZCI6IjAiLCJhbHBuIjoiIiwiZnAiOiIiLCJob3N0IjoiIiwiaWQiOiJkNDNlZTVlMy0xYjA3LTU2ZDctYjJlYS04ZDIyYzQ0ZmRjNjYiLCJuZXQiOiJ0Y3AiLCJwYXRoIjoiIiwicG9ydCI6IjgwODAiLCJzY3kiOiJjaGFjaGEyMC1wb2x5MTMwNSIsInNuaSI6IiIsInRscyI6IiIsInR5cGUiOiJub25lIiwidiI6IjIiLCJwcyI6Ilx1MDYzMVx1MDYyN1x1MDZjY1x1MDZhZlx1MDYyN1x1MDY0NiB8IFZNRVNTIHwgQFdhdGFzaGlfVlBOIHwgQVVcdWQ4M2NcdWRkZTZcdWQ4M2NcdWRkZmEgfCAwXHVmZTBmXHUyMGUzMVx1ZmUwZlx1MjBlMyJ9"

	// Define the expected JSON structure
	expectedJSON := `
	{
		"outbounds": [
		  {
			"type": "vmess",
			"tag": "رایگان | VMESS | @Watashi_VPN | AU🇦🇺 | 0️⃣1️⃣ § 0",
			"server": "51.161.130.173",
			"server_port": 8080,
			"uuid": "d43ee5e3-1b07-56d7-b2ea-8d22c44fdc66",
			"security": "chacha20-poly1305",
			"authenticated_length": true			
		  }
		]
	  }
	`
	ray2sing.CheckUrlAndJson(url, expectedJSON, t)
}

func TestVmess_TlsWebsocket(t *testing.T) {
	url := "vmess://eyJhZGQiOiI1MS4xNjEuMTMwLjE3MyIsImFpZCI6IjAiLCJhbHBuIjoiIiwiZnAiOiJjaHJvbWUiLCJob3N0Ijoidm1lc3MuZXhhbXBsZS5jb20iLCJpZCI6ImQ0M2VlNWUzLTFiMDctNTZkNy1iMmVhLThkMjJjNDRmZGM2NiIsIm5ldCI6IndzIiwicGF0aCI6Ii92bWVzc3BhdGgiLCJwb3J0IjoiNDQzIiwic2N5IjoiYXV0byIsInNuaSI6InZtZXNzLmV4YW1wbGUuY29tIiwidGxzIjoidGxzIiwidHlwZSI6Im5vbmUiLCJ2IjoiMiIsInBzIjoidm1lc3MtdGxzLXdzLXRlc3QifQo="

	expectedJSON := `
	{
		"outbounds": [
		  {
			"type": "vmess",
			"tag": "vmess-tls-ws-test § 0",
			"server": "51.161.130.173",
			"server_port": 443,
			"uuid": "d43ee5e3-1b07-56d7-b2ea-8d22c44fdc66",
			"security": "auto",
			"authenticated_length": true,
			"packet_encoding": "xudp",
			"tls": {
			  "enabled": true,
			  "server_name": "vmess.example.com",
			  "alpn": "http/1.1",
			  "utls": {
				"enabled": true,
				"fingerprint": "chrome"
			  }
			},
			"transport": {
			  "type": "ws",
			  "path": "/vmesspath",
			  "headers": {
				"Host": "vmess.example.com"
			  },
			  "early_data_header_name": "Sec-WebSocket-Protocol"
			}
		  }
		]
	  }
	`
	ray2sing.CheckUrlAndJson(url, expectedJSON, t)
}
