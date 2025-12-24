package utils

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/runes"
	"golang.org/x/text/unicode/norm"
)

type Options struct {
	Separator      rune // usually '-' or '_'
	Lowercase      bool
	MaxLength      int  // 0 = unlimited
	AsciiOnly      bool // true = transliterate to ASCII
	AllowUnicode   bool // keep non-latin scripts
	TrimSeparator  bool
	Fallback       string // used if slug becomes empty
}

// DefaultOptions returns safe production defaults
func DefaultOptions() Options {
	return Options{
		Separator:     '-',
		Lowercase:     true,
		MaxLength:     0,
		AsciiOnly:     false,
		AllowUnicode:  true,
		TrimSeparator: true,
		Fallback:      "n-a",
	}
}

// Make converts any Unicode string into a URL-safe slug
func Make(input string, opts ...Options) string {
	var opt Options
	if len(opts) > 0 {
		opt = opts[0]
	} else {
		opt = DefaultOptions()
	}
	if strings.TrimSpace(input) == "" {
		return opt.Fallback
	}

	// 1. Normalize Unicode (NFKD)
	s := norm.NFKD.String(input)

	// 2. Remove diacritics
	s = runes.Remove(runes.In(unicode.Mn)).String(s)

	var b strings.Builder
	b.Grow(len(s))

	lastWasSep := false

	for _, r := range s {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			if opt.AsciiOnly && r > unicode.MaxASCII {
				continue
			}
			b.WriteRune(r)
			lastWasSep = false

		case opt.AllowUnicode && r > unicode.MaxASCII && unicode.IsLetter(r):
			b.WriteRune(r)
			lastWasSep = false

		default:
			if !lastWasSep {
				b.WriteRune(opt.Separator)
				lastWasSep = true
			}
		}
	}

	slug := b.String()

	if opt.Lowercase {
		slug = strings.ToLower(slug)
	}

	if opt.TrimSeparator {
		slug = strings.Trim(slug, string(opt.Separator))
	}

	if opt.MaxLength > 0 && utf8.RuneCountInString(slug) > opt.MaxLength {
		slug = truncateRunes(slug, opt.MaxLength)
	}

	if slug == "" {
		return opt.Fallback
	}

	return slug
}

func truncateRunes(s string, max int) string {
	var b strings.Builder
	count := 0
	for _, r := range s {
		if count >= max {
			break
		}
		b.WriteRune(r)
		count++
	}
	return b.String()
}
