// Copyright (C) 2013-2018 by Maxim Bublis <b@codemonkey.ru>
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package uuid

import (
	"errors"
	"fmt"
)

// FromBytes returns a UUID generated from the raw byte slice input.
// It will return an error if the slice isn't 16 bytes long.
func FromBytes(input []byte) (UUID, error) {
	u := UUID{}
	err := u.UnmarshalBinary(input)
	return u, err
}

// FromBytesOrNil returns a UUID generated from the raw byte slice input.
// Same behavior as FromBytes(), but returns uuid.Nil instead of an error.
func FromBytesOrNil(input []byte) UUID {
	uuid, err := FromBytes(input)
	if err != nil {
		return Nil
	}
	return uuid
}

// FromString returns a UUID parsed from the input string.
// Input is expected in a form accepted by UnmarshalText.
func FromString(input string) (UUID, error) {
	u := UUID{}
	err := u.UnmarshalText([]byte(input))
	return u, err
}

// FromStringOrNil returns a UUID parsed from the input string.
// Same behavior as FromString(), but returns uuid.Nil instead of an error.
func FromStringOrNil(input string) UUID {
	uuid, err := FromString(input)
	if err != nil {
		return Nil
	}
	return uuid
}

// MarshalText implements the encoding.TextMarshaler interface.
// The encoding is the same as returned by the String() method.
func (u UUID) MarshalText() ([]byte, error) {
	var buf [36]byte
	encodeHex(buf[:], u)
	return buf[:], nil
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
// Following formats are supported:
//
//   "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
//   "{6ba7b810-9dad-11d1-80b4-00c04fd430c8}",
//   "urn:uuid:6ba7b810-9dad-11d1-80b4-00c04fd430c8"
//   "6ba7b8109dad11d180b400c04fd430c8"
//   "{6ba7b8109dad11d180b400c04fd430c8}",
//   "urn:uuid:6ba7b8109dad11d180b400c04fd430c8"
//
// ABNF for supported UUID text representation follows:
//
//   URN := 'urn'
//   UUID-NID := 'uuid'
//
//   hexdig := '0' | '1' | '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9' |
//             'a' | 'b' | 'c' | 'd' | 'e' | 'f' |
//             'A' | 'B' | 'C' | 'D' | 'E' | 'F'
//
//   hexoct := hexdig hexdig
//   2hexoct := hexoct hexoct
//   4hexoct := 2hexoct 2hexoct
//   6hexoct := 4hexoct 2hexoct
//   12hexoct := 6hexoct 6hexoct
//
//   hashlike := 12hexoct
//   canonical := 4hexoct '-' 2hexoct '-' 2hexoct '-' 6hexoct
//
//   plain := canonical | hashlike
//   uuid := canonical | hashlike | braced | urn
//
//   braced := '{' plain '}' | '{' hashlike  '}'
//   urn := URN ':' UUID-NID ':' plain
//
func (u *UUID) UnmarshalText(text []byte) error {
	switch len(text) {
	case 32: // hash
	case 36: // canonical
	case 34, 38:
		if text[0] != '{' || text[len(text)-1] != '}' {
			return fmt.Errorf("uuid: incorrect UUID format in string %q", text)
		}
		text = text[1 : len(text)-1]
	case 41, 45:
		if string(text[:9]) != "urn:uuid:" {
			return fmt.Errorf("uuid: incorrect UUID format in string %q", text[:9])
		}
		text = text[9:]
	default:
		return fmt.Errorf("uuid: incorrect UUID length %d in string %q", len(text), text)
	}
	if len(text) == 36 {
		return u.decodeCanonical(text)
	}
	return u.decodeHashLike(text)
}

func fromHexChar(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

var errInvalidFormat = errors.New("invalid UUID format")

// decodeCanonical decodes UUID strings that are formatted as defined in RFC-4122 (section 3):
// "6ba7b810-9dad-11d1-80b4-00c04fd430c8".
func (u *UUID) decodeCanonical(t []byte) error {
	if t[8] != '-' || t[13] != '-' || t[18] != '-' || t[23] != '-' {
		return fmt.Errorf("uuid: incorrect UUID format in string %q", t)
	}

	for i, x := range [16]int{
		0, 2, 4, 6,
		9, 11,
		14, 16,
		19, 21,
		24, 26, 28, 30, 32, 34,
	} {
		a, ok1 := fromHexChar(t[x])
		b, ok2 := fromHexChar(t[x+1])
		if ok1 && ok2 {
			u[i] = (a << 4) | b
		} else {
			return errInvalidFormat
		}
	}
	return nil
}

// decodeHashLike decodes UUID strings that are using the following format:
//  "6ba7b8109dad11d180b400c04fd430c8".
func (u *UUID) decodeHashLike(t []byte) error {
	for i := 0; i < 32; i += 2 {
		a, ok1 := fromHexChar(t[i])
		b, ok2 := fromHexChar(t[i+1])
		if ok1 && ok2 {
			u[i/2] = (a << 4) | b
		} else {
			return errInvalidFormat
		}
	}
	return nil
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (u UUID) MarshalBinary() ([]byte, error) {
	return u.Bytes(), nil
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
// It will return an error if the slice isn't 16 bytes long.
func (u *UUID) UnmarshalBinary(data []byte) error {
	if len(data) != Size {
		return fmt.Errorf("uuid: UUID must be exactly 16 bytes long, got %d bytes", len(data))
	}
	copy(u[:], data)

	return nil
}
