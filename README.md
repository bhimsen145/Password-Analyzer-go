**Password Strength Analyzer (Go)**


A command-line tool written in Go that analyzes password strength using entropy calculation and pattern detection and gives a strength score with actionable recommendations.

## Features

- **Entropy calculation** — measures password randomness in bits
- **Strength scoring** — rates passwords on a 1–5 scale
- **Pattern detection** — flags weak patterns like ascending sequences (`abc`, `123`), repeated characters, and common substrings
- **Actionable recommendations** — tells you specifically what to fix

## Example Output

```
Enter Password:
Analysing...

--- Results ---
Length:   13 characters
Score:    5/5
Entropy:  85.21 bits
Strength: [██████████] Very Strong

Warnings:
  ⚠ Contains an ascending sequence (e.g. abc, 123)

Recommendations:
  - Avoid sequential patterns like 'abc' or '123'
```

Note how even a password with high entropy (85 bits) can still get flagged — a strong length/character mix doesn't guarantee it's free of predictable patterns.

## How It Works

1. **Entropy** is calculated based on password length and the character set used (lowercase, uppercase, digits, symbols), giving a bits-of-randomness estimate.
2. **Pattern checks** scan for common weaknesses that entropy alone won't catch — sequences, repeated characters, keyboard walks, etc.
3. Both are combined into a final **score (1–5)** and a human-readable **strength label**.

## Installation & Usage

Requires [Go](https://go.dev/dl/) installed.

```bash
git clone https://github.com/yourusername/password-analyzer-go.git
cd password-analyzer-go
go run main.go
```

Then enter a password when prompted.

## Roadmap / Ideas

- [ ] Add a `-file` flag to batch-check a list of passwords
- [ ] Export results as JSON
- [ ] Add a "time to crack" estimate

<img width="644" height="689" alt="Screenshot from 2026-09-27 21-29-01" src="https://github.com/user-attachments/assets/f1a4d38c-c2db-4467-8772-d33922af6d1c" />

