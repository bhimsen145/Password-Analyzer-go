package main

import (
	"fmt"
	"math"
	"unicode"
	"unicode/utf8"
)

// guessesPerSecond models an offline attack on a fast hash (e.g. MD5/SHA-1)
// with a modern GPU rig: roughly 10 billion guesses per second.
const guessesPerSecond = 1e10

// quickEntropy estimates entropy in bits: length * log2(size of character pool).
// Pool: 26 lowercase + 26 uppercase + 10 digits + 32 symbols.
func quickEntropy(password string) float64 {
	pool := 0
	var lower, upper, digit, other bool
	for _, r := range password {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			other = true
		}
	}
	if lower {
		pool += 26
	}
	if upper {
		pool += 26
	}
	if digit {
		pool += 10
	}
	if other {
		pool += 32
	}
	if pool == 0 {
		return 0
	}
	return float64(utf8.RuneCountInString(password)) * math.Log2(float64(pool))
}

// crackTimeSeconds returns the AVERAGE time to guess a random password with the
// given entropy: half the search space divided by the guess rate.
func crackTimeSeconds(entropyBits float64) float64 {
	return math.Pow(2, entropyBits) / 2 / guessesPerSecond
}

// humanDuration turns seconds into friendly text like "3 days" or "millions of years".
func humanDuration(seconds float64) string {
	const (
		minute = 60.0
		hour   = 60 * minute
		day    = 24 * hour
		year   = 365 * day
	)
	switch {
	case math.IsInf(seconds, 1) || seconds > 1.4e10*year: // universe is ~13.8 billion years old
		return "longer than the age of the universe"
	case seconds < 1:
		return "instantly"
	case seconds < minute:
		return plural(seconds, "second")
	case seconds < hour:
		return plural(seconds/minute, "minute")
	case seconds < day:
		return plural(seconds/hour, "hour")
	case seconds < year:
		return plural(seconds/day, "day")
	case seconds < 1e3*year:
		return plural(seconds/year, "year")
	case seconds < 1e6*year:
		return "thousands of years"
	case seconds < 1e9*year:
		return "millions of years"
	default:
		return "billions of years"
	}
}

func plural(value float64, unit string) string {
	n := int(math.Round(value))
	if n < 1 {
		n = 1
	}
	if n == 1 {
		return fmt.Sprintf("1 %s", unit)
	}
	return fmt.Sprintf("%d %ss", n, unit)
}
