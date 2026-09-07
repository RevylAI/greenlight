package codescan

import (
	"regexp"
	"strings"
)

var (
	rePreprocIf    = regexp.MustCompile(`^\s*#\s*if(n?def)?\b(.*)$`)
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
// swallowed: conditions we cannot evaluate (#elif, compound or negated #if,
// non-guard #if) are live, and an unbalanced file suppresses nothing at all.
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
			g := guardProvesBranchDead(line, guards)
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

// guardProvesBranchDead reports whether a #if line's condition is *exactly* one
// of the guards.
//
// Containment is not enough. `#if !(__IPHONE_OS_VERSION_MIN_REQUIRED <
// __IPHONE_9_0)` and `#if defined(LEGACY_SHIM) || __IPHONE_OS_VERSION_MIN_REQUIRED
// < __IPHONE_9_0` both contain the guard while compiling on every modern
// deployment target — reading them as dead switches a hard-rejection rule off
// for code that actually ships. We do not evaluate preprocessor expressions, so
// anything carrying `!`, `||` or `&&`, and every `#ifndef`, resolves to live.
func guardProvesBranchDead(line string, guards []*regexp.Regexp) bool {
	m := rePreprocIf.FindStringSubmatch(line)
	if m == nil {
		return false
	}
	if m[1] == "ndef" { // #ifndef GUARD is the negation of the guard
		return false
	}

	cond := strings.TrimSpace(stripStringsAndComments(m[2]))
	// Peel wrapping parens so `#if (GUARD)` reads the same as `#if GUARD`, but
	// only when they enclose the whole condition — `(a) || (b)` must not shed to
	// `a) || (b`.
	for len(cond) > 1 && cond[0] == '(' && parenSpan(cond) == len(cond) {
		cond = strings.TrimSpace(cond[1 : len(cond)-1])
	}
	if cond == "" || strings.ContainsAny(cond, "!") ||
		strings.Contains(cond, "||") || strings.Contains(cond, "&&") {
		return false
	}

	for _, p := range guards {
		if loc := p.FindStringIndex(cond); loc != nil && loc[0] == 0 && loc[1] == len(cond) {
			return true
		}
	}
	return false
}

// parenSpan returns the index just past the paren that closes the one at s[0],
// or -1 if it never closes.
func parenSpan(s string) int {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return -1
}
