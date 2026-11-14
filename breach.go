package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// breachAPIBase is a variable (not a constant) so tests can point it at a fake server.
var breachAPIBase = "https://api.pwnedpasswords.com/range/"

// checkBreach asks the Have I Been Pwned "Pwned Passwords" API how many times
// a password appears in known data breaches. It returns 0 if it was not found.
//
// Privacy (k-anonymity): the password is hashed locally with SHA-1 and ONLY the
// first 5 characters of the hash are sent. The API replies with every leaked
// hash that starts with those 5 characters, and we compare the rest locally.
// The password and the full hash never leave this computer.
func checkBreach(password string) (int, error) {
	sum := sha1.Sum([]byte(password))
	hash := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := hash[:5], hash[5:]

	req, err := http.NewRequest(http.MethodGet, breachAPIBase+prefix, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "password-analyzer-go")
	// Padding makes the response size less revealing; padded entries have count 0.
	req.Header.Set("Add-Padding", "true")

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("could not reach breach database: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("breach database returned status %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 || parts[0] != suffix {
			continue
		}
		count, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return 0, fmt.Errorf("unexpected response format: %w", err)
		}
		return count, nil
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, nil
}

// formatCount adds thousands separators: 10000000 -> "10,000,000".
func formatCount(n int) string {
	s := strconv.Itoa(n)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	pre := len(s) % 3
	if pre > 0 {
		b.WriteString(s[:pre])
	}
	for i := pre; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s[i : i+3])
	}
	return b.String()
}
