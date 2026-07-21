package ray2sing

import (
	"regexp"
	"sort"
	"strings"
)

func buildRegex() *regexp.Regexp {
	prefixSet := map[string]struct{}{
		"#":  {},
		"//": {},
	}

	for k := range configTypes {
		prefixSet[k] = struct{}{}
	}
	for k := range endpointParsers {
		prefixSet[k] = struct{}{}
	}
	for k := range xrayConfigTypes {
		prefixSet[k] = struct{}{}
	}

	var prefixes []string
	for k := range prefixSet {
		prefixes = append(prefixes, ""+regexp.QuoteMeta(k))
	}

	// IMPORTANT: longest first
	sort.Slice(prefixes, func(i, j int) bool {
		return len(prefixes[i]) > len(prefixes[j])
	})

	// pattern := `(` + strings.Join(prefixes, "|") + `)`
	pattern := `(?m)^(?:` + strings.Join(prefixes, "|") + `)`

	return regexp.MustCompile(pattern)
}

var splitPattern = buildRegex()

func splitByPrefix(text string) []string {
	indexes := splitPattern.FindAllStringIndex(text, -1)

	if len(indexes) == 0 {
		return []string{text}
	}

	var result []string

	// Preserve header
	// if indexes[0][0] > 0 {
	// 	result = append(result, text[:indexes[0][0]])
	// }

	for i := 0; i < len(indexes); i++ {
		start := indexes[i][0]

		var end int
		if i+1 < len(indexes) {
			end = indexes[i+1][0]
		} else {
			end = len(text)
		}

		result = append(result, text[start:end])
	}

	return result
}
func expandDecodedConfig(configs string) []string {
	res := []string{}
	add := func(config ...string) {
		for _, c := range config {
			tc := strings.TrimSpace(c)
			if tc == "" || tc[0] == '#' || tc[0] == '/' {
				continue
			}
			res = append(res, tc)
		}
	}

	configs2 := []string{}
	for _, config := range strings.Split(configs, "\n") {
		configDecoded, err := decodeBase64IfNeeded(config)
		if err != nil {
			configDecoded = config
		}
		configs2 = append(configs2, strings.Split(strings.ReplaceAll(configDecoded, "\r", "\n"), "\n")...)
	}

	newConfigs := mergeInterfaceBlocks(splitByPrefix(strings.Join(configs2, "\n")))

	add(newConfigs...)

	return res
}

// mergeInterfaceBlocks re-joins the pieces splitByPrefix produces from a single wg-quick/AmneziaWG
// "[Interface]"/"[Peer]" block. Those blocks commonly carry their own "# Name = ..." comment lines
// (a wg-quick/Amnezia convention) inside the section body - and splitByPrefix's bare "#" boundary
// (needed so a genuine "# label" comment line ahead of the next real config isn't glued onto it)
// treats each of those as the start of a new chunk too, shredding the block down to just its
// "[Interface]" header before AWGSingboxTxt ever sees it. Since a "[Interface]" block only ever
// legitimately ends at the next real config prefix (a "scheme://" or another "[Interface]"), merge
// everything up to that point back together, wherever it came from.
func mergeInterfaceBlocks(chunks []string) []string {
	var merged []string
	for i := 0; i < len(chunks); i++ {
		if !strings.HasPrefix(strings.TrimSpace(chunks[i]), "[Interface]") {
			merged = append(merged, chunks[i])
			continue
		}
		block := chunks[i]
		j := i + 1
		for j < len(chunks) && !isNewConfigChunk(chunks[j]) {
			block += "\n" + chunks[j]
			j++
		}
		merged = append(merged, block)
		i = j - 1
	}
	return merged
}

// isNewConfigChunk reports whether a chunk begins a genuinely new config entry (a registered
// scheme prefix, or another "[Interface]" block) as opposed to a comment/continuation line that
// only looks like a boundary to splitByPrefix's generic "#" handling.
func isNewConfigChunk(chunk string) bool {
	trimmed := strings.TrimSpace(chunk)
	if strings.HasPrefix(trimmed, "[Interface]") {
		return true
	}
	for k := range configTypes {
		if strings.HasPrefix(trimmed, k) {
			return true
		}
	}
	for k := range xrayConfigTypes {
		if strings.HasPrefix(trimmed, k) {
			return true
		}
	}
	for k := range endpointParsers {
		if k != "[Interface]" && strings.HasPrefix(trimmed, k) {
			return true
		}
	}
	return false
}
