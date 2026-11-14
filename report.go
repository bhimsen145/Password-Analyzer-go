package main

import (
	"fmt"
	"math"
	"unicode/utf8"
)

// Report is one password's result in batch / JSON mode.
// The password itself is NEVER included in the output, only its line number.
type Report struct {
	Line          int     `json:"line"`
	Length        int     `json:"length"`
	EntropyBits   float64 `json:"entropy_bits"`
	CrackTime     string  `json:"estimated_crack_time"`
	BreachChecked bool    `json:"breach_checked"`
	Breached      bool    `json:"breached"`
	BreachCount   int     `json:"breach_count"`
	Error         string  `json:"error,omitempty"`
}

// buildReport computes the statistics for one password.
func buildReport(line int, password string, checkOnline bool) Report {
	bits := quickEntropy(password)
	r := Report{
		Line:        line,
		Length:      utf8.RuneCountInString(password),
		EntropyBits: math.Round(bits*10) / 10,
		CrackTime:   humanDuration(crackTimeSeconds(bits)),
	}
	if checkOnline {
		count, err := checkBreach(password)
		if err != nil {
			r.Error = err.Error()
		} else {
			r.BreachChecked = true
			r.BreachCount = count
			r.Breached = count > 0
		}
	}
	return r
}

// printExtras prints the new statistics in the normal interactive mode.
// Call it at the end of main(), passing the password string.
func printExtras(password string) {
	bits := quickEntropy(password)
	fmt.Printf("\nCrack time:   %s (average, offline attack at 10 billion guesses/sec)\n", humanDuration(crackTimeSeconds(bits)))

	if offlineMode {
		fmt.Println("Breach check: skipped (-offline)")
		return
	}
	count, err := checkBreach(password)
	switch {
	case err != nil:
		fmt.Printf("Breach check: unavailable (%v)\n", err)
	case count > 0:
		fmt.Printf("Breach check: FOUND in %s known breaches. Never use this password!\n", formatCount(count))
	default:
		fmt.Println("Breach check: not found in known breaches")
	}
}
