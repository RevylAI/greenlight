package codescan

import "regexp"

var (
	rePreprocIf    = regexp.MustCompile(`^\s*#\s*if(n?def)?\b`)
	rePreprocElse  = regexp.MustCompile(`^\s*#\s*else\b`)
	rePreprocElif  = regexp.MustCompile(`^\s*#\s*elif\b`)
	rePreprocEndif = regexp.MustCompile(`^\s*#\s*endif\b`)
)

// deadLines reports which line indices sit inside a preprocessor branch that one
// of guards proves the compiler never emits — e.g. a legacy shim wrapped in
// `#if __IPHONE_OS_VERSION_MIN_REQUIRED < __IPHONE_9_0`.
//
// Suppression must be line-precise. Treating "the guard appears somewhere in
// this file" as "the whole file is dead" would hide live code that follows the
// matching #endif, turning a false positive into the far worse false negative of
// a CRITICAL rejection reason going unreported.
//
// Every ambiguity resolves toward "live", so a finding is reported rather than
// swallowed: conditions we cannot evaluate (#elif, non-guard #if) are live, and
// an unbalanced file suppresses nothing at all.
func deadLines(lines []string, guards []*regexp.Regexp) map[int]bool {
	// guarded records whether this level's branch state is one we actually
	// derived from a guard — only then may #else flip it.
	type frame struct{ guarded, dead bool }
	var stack []frame

	dead := make(map[int]bool)
	inDead := func() bool {
		for _, f := range stack {
			if f.dead {
				return true
			}
		}
		return false
	}

	for i, line := range lines {
		switch {
		case rePreprocIf.MatchString(line):
			g := matchesAny(guards, line)
			stack = append(stack, frame{guarded: g, dead: g})
		case rePreprocElse.MatchString(line) && len(stack) > 0:
			if top := &stack[len(stack)-1]; top.guarded {
				top.dead = !top.dead
			}
		case rePreprocElif.MatchString(line) && len(stack) > 0:
			// The new condition is not the guard we matched, and we do not
			// evaluate preprocessor expressions — assume the branch ships.
			if top := &stack[len(stack)-1]; top.guarded {
				top.guarded, top.dead = false, false
			}
		case rePreprocEndif.MatchString(line) && len(stack) > 0:
			stack = stack[:len(stack)-1]
		}

		if inDead() {
			dead[i] = true
		}
	}

	// Unbalanced directives mean we lost track of the nesting; suppress nothing.
	if len(stack) != 0 {
		return nil
	}
	return dead
}

func matchesAny(patterns []*regexp.Regexp, s string) bool {
	for _, p := range patterns {
		if p.MatchString(s) {
			return true
		}
	}
	return false
}
