package main

import (
	_ "embed"
	"fmt"
	"math"
	"os"
	"strings"
	"unicode"

	"golang.org/x/term"
)

// common-passwords.txt is embedded directly into the binary at compile time.
// Drop any .txt list next to this file and it will be bundled automatically.
//
//go:embed common-passwords.txt
var passwordListFile string

// commonPasswordSet is built once at startup for O(1) lookups.
var commonPasswordSet map[string]struct{}

func init() {
	commonPasswordSet = make(map[string]struct{})
	for _, line := range strings.Split(passwordListFile, "\n") {
		word := strings.ToLower(strings.TrimSpace(line))
		if word != "" {
			commonPasswordSet[word] = struct{}{}
		}
	}
}

// isCommon checks if a password appears in the embedded common-passwords list.
func isCommon(password string) bool {
	_, found := commonPasswordSet[strings.ToLower(password)]
	return found
}

// hasSequence detects ascending character sequences of 3 or more (e.g. "abc", "123").
func hasSequence(password string) bool {
	for i := 0; i < len(password)-2; i++ {
		if password[i]+1 == password[i+1] &&
			password[i]+2 == password[i+2] {
			return true
		}
	}
	return false
}

// hasRepeat detects 3 or more consecutive identical characters (e.g. "aaa").
func hasRepeat(password string) bool {
	count := 1
	for i := 1; i < len(password); i++ {
		if password[i] == password[i-1] {
			count++
			if count >= 3 {
				return true
			}
		} else {
			count = 1
		}
	}
	return false
}

// calculateEntropy estimates password entropy based on character pool size.
func calculateEntropy(password string) float64 {
	var pool int
	hasLower := false
	hasUpper := false
	hasDigit := false
	hasSymbol := false

	for _, c := range password {
		switch {
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsDigit(c):
			hasDigit = true
		default:
			hasSymbol = true
		}
	}

	if hasLower {
		pool += 26
	}
	if hasUpper {
		pool += 26
	}
	if hasDigit {
		pool += 10
	}
	if hasSymbol {
		pool += 32
	}
	if pool == 0 {
		return 0
	}

	return float64(len(password)) * math.Log2(float64(pool))
}

// classify maps an entropy value to a human-readable strength label.
func classify(entropy float64) string {
	switch {
	case entropy < 28:
		return "Very Weak"
	case entropy < 36:
		return "Weak"
	case entropy < 60:
		return "Reasonable"
	case entropy < 80:
		return "Strong"
	default:
		return "Very Strong"
	}
}

// strengthBar returns a simple visual bar for the strength level.
func strengthBar(entropy float64) string {
	bars := int(entropy / 20)
	if bars > 5 {
		bars = 5
	}
	filled := strings.Repeat("█", bars)
	empty := strings.Repeat("░", 5-bars)
	return fmt.Sprintf("[%s%s]", filled, empty)
}

// calculateScore returns a 0–5 score based on password composition rules.
func calculateScore(password string) int {
	score := 0

	if len(password) >= 8 {
		score++
	}
	if len(password) >= 12 {
		score++
	}

	hasDigit := false
	hasUpper := false
	hasLower := false
	hasSpecial := false

	for _, c := range password {
		switch {
		case unicode.IsDigit(c):
			hasDigit = true
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		default:
			hasSpecial = true
		}
	}

	if hasDigit {
		score++
	}
	if hasUpper && hasLower {
		score++
	}
	if hasSpecial {
		score++
	}

	return score
}

func main() {
	fmt.Print("Enter Password: ")
	bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Println("\nError reading password:", err)
		os.Exit(1)
	}
	password := string(bytePassword)
	fmt.Println()

	if len(password) == 0 {
		fmt.Println("No password entered.")
		os.Exit(1)
	}

	fmt.Println("Analysing...")

	// --- Warnings ---
	warnings := []string{}

	if isCommon(password) {
		warnings = append(warnings, "⚠  This is one of the most commonly used passwords — change it immediately!")
	}
	if hasSequence(password) {
		warnings = append(warnings, "⚠  Contains an ascending sequence (e.g. abc, 123)")
	}
	if hasRepeat(password) {
		warnings = append(warnings, "⚠  Contains 3+ repeated consecutive characters (e.g. aaa)")
	}

	// --- Scoring ---
	score := calculateScore(password)
	entropy := calculateEntropy(password)
	strength := classify(entropy)
	bar := strengthBar(entropy)

	// --- Output ---
	fmt.Println("\n--- Results ---")
	fmt.Printf("Length:   %d characters\n", len(password))
	fmt.Printf("Score:    %d/5\n", score)
	fmt.Printf("Entropy:  %.2f bits\n", entropy)
	fmt.Printf("Strength: %s %s\n", bar, strength)

	if len(warnings) > 0 {
		fmt.Println("\nWarnings:")
		for _, w := range warnings {
			fmt.Println(" ", w)
		}
	}

	// --- Recommendations ---
	recs := []string{}

	if len(password) < 12 {
		recs = append(recs, "Use at least 12 characters")
	}
	if !strings.ContainsAny(password, "!@#$%^&*()-_=+[]{}|;:',.<>?/`~") {
		recs = append(recs, "Add special characters (e.g. !, @, #, $)")
	}
	if !strings.ContainsAny(password, "0123456789") {
		recs = append(recs, "Add numbers")
	}
	if password == strings.ToLower(password) {
		recs = append(recs, "Add uppercase letters")
	}
	if password == strings.ToUpper(password) {
		recs = append(recs, "Add lowercase letters")
	}
	if hasSequence(password) {
		recs = append(recs, "Avoid sequential patterns like 'abc' or '123'")
	}
	if hasRepeat(password) {
		recs = append(recs, "Avoid repeating the same character multiple times")
	}

	if len(recs) > 0 {
		fmt.Println("\nRecommendations:")
		for _, r := range recs {
			fmt.Println(" -", r)
		}
	} else {
		fmt.Println("\n✓ Great password! No recommendations.")
	}
}
