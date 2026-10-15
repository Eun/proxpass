// Package loglevel interprets the --log-level flag.
//
// proxpass logs to one place per process -- stderr -- so a level is a
// filter on what is worth saying, not a routing decision. There are four,
// matching what the flag has always advertised, and the only distinction
// the code makes today is debug-or-not: everything logged before this
// existed is info, and the diagnostics that answer "why did this session
// do that" are debug.
//
// Deliberately not a logging library. A level that gates a handful of
// Printf calls does not need structured fields, handlers or a context,
// and introducing those would be a far larger change than the question
// being answered.
package loglevel

import (
	"fmt"
	"strings"
)

// Level is how much a process says.
type Level int

// The levels, ordered from most verbose to least. Comparing them is what
// makes Enabled work, so the order matters more than the values.
const (
	Debug Level = iota
	Info
	Warn
	Error
)

// Default is the level a process runs at when none is given.
const Default = Info

// infoName is the flag spelling of the default level, which appears both
// as an accepted input and as the fallback rendering.
const infoName = "info"

// Parse turns the flag's value into a Level.
//
// Case-insensitive, because proxpass matches names that way everywhere
// else and a level typed as DEBUG should not be an error.
//
// An unknown value IS an error rather than a silent fallback: a typo in
// --log-level would otherwise leave an operator waiting for diagnostics
// that were never switched on.
func Parse(s string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return Debug, nil
	case infoName, "":
		return Info, nil
	case "warn", "warning":
		return Warn, nil
	case "error":
		return Error, nil
	default:
		return Default, fmt.Errorf(
			"unknown log level %q: use debug, info, warn or error", s)
	}
}

// String renders the level as the flag spells it.
func (l Level) String() string {
	switch l {
	case Debug:
		return "debug"
	case Info:
		return infoName
	case Warn:
		return "warn"
	case Error:
		return "error"
	default:
		return infoName
	}
}

// Enabled reports whether a message at want should be written.
func (l Level) Enabled(want Level) bool { return want >= l }
