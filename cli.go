package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

var (
	fileFlag    = flag.String("file", "", "check every password in a text file (one per line)")
	jsonFlag    = flag.Bool("json", false, "print batch results as JSON")
	offlineFlag = flag.Bool("offline", false, "skip the online breach check")

	// offlineMode is read by printExtras.
	offlineMode bool
)

// runCLI parses flags. It returns true if it handled the whole request (batch
// mode), in which case main() should return immediately. When it returns
// false, main() continues with the normal interactive prompt.
func runCLI() bool {
	flag.Parse()
	offlineMode = *offlineFlag

	if *fileFlag == "" {
		return false
	}

	anyBreached, err := runBatch(*fileFlag, *jsonFlag, offlineMode)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	if anyBreached {
		os.Exit(1) // non-zero exit code so scripts / CI can react
	}
	return true
}

// runBatch checks every non-empty line of a file and prints a table or JSON.
func runBatch(path string, asJSON, offline bool) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	var reports []Report
	anyBreached := false
	scanner := bufio.NewScanner(f)
	line := 0
	for scanner.Scan() {
		line++
		pw := strings.TrimRight(scanner.Text(), "\r")
		if pw == "" {
			continue
		}
		r := buildReport(line, pw, !offline)
		if r.Breached {
			anyBreached = true
		}
		reports = append(reports, r)
		if !offline {
			time.Sleep(50 * time.Millisecond) // be polite to the API
		}
	}
	if err := scanner.Err(); err != nil {
		return false, err
	}

	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return anyBreached, enc.Encode(reports)
	}

	fmt.Printf("%-6s %-7s %-9s %-37s %s\n", "LINE", "LENGTH", "ENTROPY", "CRACK TIME", "BREACHES")
	for _, r := range reports {
		breach := "not checked"
		switch {
		case r.Error != "":
			breach = "error"
		case r.Breached:
			breach = formatCount(r.BreachCount)
		case r.BreachChecked:
			breach = "none found"
		}
		fmt.Printf("%-6d %-7d %-9.1f %-37s %s\n", r.Line, r.Length, r.EntropyBits, r.CrackTime, breach)
	}
	return anyBreached, nil
}
