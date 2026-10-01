package session

import (
	"io"
	"unicode/utf8"
)

// keyKind classifies a decoded keystroke.
type keyKind int

const (
	keyRune keyKind = iota
	keyEnter
	keyEsc
	keyUp
	keyDown
	keyLeft
	keyRight
	keyHome
	keyEnd
	keyPageUp
	keyPageDown
	keyBackspace
	keyCtrlC
	keyCtrlU
	keyTab
	keyShiftTab
	keyUnknown
)

// key is one decoded keystroke.
type key struct {
	kind keyKind
	r    rune
}

// Control bytes a raw-mode terminal delivers.
const (
	byteCtrlC     = 0x03
	byteCtrlU     = 0x15
	byteEsc       = 0x1b
	byteCR        = 0x0d
	byteLF        = 0x0a
	byteBackspace = 0x08
	byteDelete    = 0x7f
	byteTab       = 0x09
)

// readKey reads and decodes a single keystroke.
//
// Input is read one byte at a time, without buffering, because the very same
// reader is handed to the guest console once a selection is made: a buffered
// reader would hold bytes the console should have received.
//
// An escape sequence is read greedily. A lone Esc is indistinguishable from
// the start of an arrow key until either more bytes arrive or they do not, so
// this relies on terminals sending the whole sequence in one burst: after
// reading Esc we attempt the following bytes and treat an unrecognized or
// truncated sequence as a plain Esc.
func readKey(r io.Reader) (key, error) {
	b, err := readByte(r)
	if err != nil {
		return key{}, err
	}

	switch b {
	case byteCtrlC:
		return key{kind: keyCtrlC}, nil
	case byteCtrlU:
		return key{kind: keyCtrlU}, nil
	case byteCR, byteLF:
		return key{kind: keyEnter}, nil
	case byteBackspace, byteDelete:
		return key{kind: keyBackspace}, nil
	case byteTab:
		// Tab is free to be a hotkey precisely because it is not a
		// printable rune: it can never be something the user meant to type
		// into the filter.
		return key{kind: keyTab}, nil
	case byteEsc:
		return readEscape(r)
	}

	if b < 0x20 {
		return key{kind: keyUnknown}, nil
	}

	// A byte >= 0x80 starts a multi-byte UTF-8 rune; gather the rest so a
	// non-ASCII guest name can be typed into the filter.
	if b < utf8.RuneSelf {
		return key{kind: keyRune, r: rune(b)}, nil
	}
	buf := []byte{b}
	for len(buf) < utf8.UTFMax {
		next, readErr := readByte(r)
		if readErr != nil {
			return key{kind: keyUnknown}, nil //nolint:nilerr // partial rune: ignore the key, not the session
		}
		buf = append(buf, next)
		if rn, _ := utf8.DecodeRune(buf); rn != utf8.RuneError {
			return key{kind: keyRune, r: rn}, nil
		}
	}
	return key{kind: keyUnknown}, nil
}

// readEscape decodes the remainder of an escape sequence.
func readEscape(r io.Reader) (key, error) {
	b, err := readByte(r)
	if err != nil {
		// Nothing followed: a bare Esc.
		return key{kind: keyEsc}, nil //nolint:nilerr // a lone Esc is a valid key
	}
	if b != '[' && b != 'O' {
		return key{kind: keyEsc}, nil
	}

	b, err = readByte(r)
	if err != nil {
		return key{kind: keyEsc}, nil //nolint:nilerr // truncated sequence
	}
	switch b {
	case 'A':
		return key{kind: keyUp}, nil
	case 'B':
		return key{kind: keyDown}, nil
	case 'C':
		return key{kind: keyRight}, nil
	case 'D':
		return key{kind: keyLeft}, nil
	case 'H':
		return key{kind: keyHome}, nil
	case 'F':
		return key{kind: keyEnd}, nil
	case 'Z':
		// CSI Z is Shift+Tab (back-tab). Terminals that do not send it
		// simply leave the user cycling forward, which still reaches every
		// mode, so this degrades without breaking anything.
		return key{kind: keyShiftTab}, nil
	}

	// "\x1b[<n>~" — Home/End/PgUp/PgDn on the terminals that use it.
	if b >= '0' && b <= '9' {
		num := int(b - '0')
		for {
			nb, readErr := readByte(r)
			if readErr != nil {
				return key{kind: keyUnknown}, nil //nolint:nilerr // truncated sequence
			}
			if nb == '~' {
				break
			}
			if nb < '0' || nb > '9' {
				return key{kind: keyUnknown}, nil
			}
			num = num*10 + int(nb-'0')
		}
		switch num {
		case 1, 7:
			return key{kind: keyHome}, nil
		case 4, 8:
			return key{kind: keyEnd}, nil
		case 5:
			return key{kind: keyPageUp}, nil
		case 6:
			return key{kind: keyPageDown}, nil
		}
	}
	return key{kind: keyUnknown}, nil
}

// readByte reads exactly one byte, retrying an empty non-error read.
func readByte(r io.Reader) (byte, error) {
	var b [1]byte
	for {
		n, err := r.Read(b[:])
		if n > 0 {
			return b[0], nil
		}
		if err != nil {
			return 0, err
		}
	}
}
