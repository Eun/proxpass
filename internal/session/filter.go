package session

import "strings"

// fuzzyScore scores needle as a fuzzy (subsequence) match of hay and reports
// whether it matched at all. A higher score is a better match.
//
// This replaces the fuzzy library the removed bubbletea picker depended on.
// The scoring only has to be good enough to rank a few hundred guest names,
// so it rewards the two things that make a guest list feel responsive:
// characters matched next to each other, and characters matched at the start
// of a word ("mw" should find "mautrix-whatsapp").
func fuzzyScore(hay, needle string) (int, bool) {
	if needle == "" {
		return 0, true
	}
	h := strings.ToLower(hay)
	n := strings.ToLower(needle)

	const (
		consecutiveBonus = 8
		wordStartBonus   = 6
		matchScore       = 1
		gapPenalty       = 1
	)

	score := 0
	hi := 0
	prevMatched := false
	for ni := 0; ni < len(n); ni++ {
		c := n[ni]
		found := -1
		for ; hi < len(h); hi++ {
			if h[hi] == c {
				found = hi
				break
			}
		}
		if found < 0 {
			return 0, false
		}
		score += matchScore
		if prevMatched {
			score += consecutiveBonus
		}
		if found == 0 || isWordBoundary(h[found-1]) {
			score += wordStartBonus
		}
		// Skipping characters is allowed but not free, so a tight match
		// outranks one scattered across the whole string.
		if !prevMatched && found > 0 {
			score -= gapPenalty
		}
		prevMatched = true
		hi = found + 1
	}
	// Prefer shorter haystacks: with equal matches, "vpn1" is a better hit
	// for "vpn" than "coder-mux-vpn-gateway".
	score -= len(h) / 16
	return score, true
}

// isWordBoundary reports whether c separates words in a guest label.
func isWordBoundary(c byte) bool {
	switch c {
	case ' ', '-', '_', '.', '/', ':', '\t':
		return true
	}
	// A digit following a letter starts a new "word" so that "ct118" is
	// reachable by typing "118".
	return c >= '0' && c <= '9'
}
