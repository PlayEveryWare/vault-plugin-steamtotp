package backend

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"strings"
	"time"
)

const (
	// steamPrefix is the URI-style prefix used by Bitwarden and other
	// authenticators to mark a key as a Steam Guard secret.
	steamPrefix = "steam://"

	// steamAlphabet is the 26-character alphabet used by Steam Guard codes.
	steamAlphabet = "23456789BCDFGHJKMNPQRTVWXY"

	// steamCodeLength is the number of characters in a Steam Guard code.
	steamCodeLength = 5

	// steamPeriod is the time step, in seconds, for Steam Guard codes.
	steamPeriod = 30
)

// normalizeKey converts a user-supplied Steam shared secret into its canonical
// base32 form. It accepts an optional (case-insensitive) "steam://" prefix,
// ignores whitespace, dashes and other separators, is case-insensitive, and
// tolerates missing "=" padding. The returned string is upper-case, padded
// base32 that decodes cleanly with base32.StdEncoding.
func normalizeKey(key string) (string, error) {
	key = strings.TrimSpace(key)
	if len(key) >= len(steamPrefix) && strings.EqualFold(key[:len(steamPrefix)], steamPrefix) {
		key = key[len(steamPrefix):]
	}

	var sb strings.Builder
	for _, r := range key {
		switch {
		case r >= 'a' && r <= 'z':
			sb.WriteRune(r - 'a' + 'A')
		case (r >= 'A' && r <= 'Z') || (r >= '2' && r <= '7'):
			sb.WriteRune(r)
		case r == '=' || r == ' ' || r == '-' || r == '_' || r == '\t' || r == '\r' || r == '\n':
			// separators and padding are ignored
		default:
			return "", errors.New("key contains characters that are not valid base32")
		}
	}

	normalized := sb.String()
	if normalized == "" {
		return "", errors.New("key is empty")
	}
	if rem := len(normalized) % 8; rem != 0 {
		normalized += strings.Repeat("=", 8-rem)
	}

	if _, err := base32.StdEncoding.DecodeString(normalized); err != nil {
		return "", errors.New("key is not valid base32")
	}

	return normalized, nil
}

// decodeKey decodes a normalized base32 key into raw secret bytes.
func decodeKey(normalized string) ([]byte, error) {
	return base32.StdEncoding.DecodeString(normalized)
}

// steamCounter returns the TOTP counter for the given time.
func steamCounter(t time.Time) uint64 {
	return uint64(t.Unix() / steamPeriod)
}

// steamCodeForCounter computes the Steam Guard code for a raw secret and a
// TOTP counter value: HMAC-SHA1, RFC 4226 dynamic truncation, then five
// base-26 digits (least significant first) over the Steam alphabet.
func steamCodeForCounter(secret []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)

	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	digest := mac.Sum(nil)

	offset := digest[len(digest)-1] & 0x0F
	bin := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7FFFFFFF

	code := make([]byte, steamCodeLength)
	for i := range code {
		code[i] = steamAlphabet[bin%uint32(len(steamAlphabet))]
		bin /= uint32(len(steamAlphabet))
	}
	return string(code)
}

// steamCode computes the Steam Guard code valid at time t.
func steamCode(secret []byte, t time.Time) string {
	return steamCodeForCounter(secret, steamCounter(t))
}
