package ray2sing

import (
	"encoding/base64"
	"strings"
)

// decodeBase64FaultTolerant tries many variants and returns the first successful decode.
// If none succeed it returns an error containing the debug attempts.
func decodeBase64FaultTolerant(raw string) (string, error) {

	raw = strings.TrimSpace(raw)
	if m := len(raw) % 4; m != 0 {
		raw += strings.Repeat("=", 4-m)
	}

	// Try URL-safe decoding
	data, err := base64.StdEncoding.DecodeString(raw)
	if err == nil {
		return string(data), nil
	}

	// Fallback to standard
	data, err = base64.URLEncoding.DecodeString(raw)
	if err != nil {
		return raw, err
	}
	return string(data), nil
}
