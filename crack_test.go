package main

import (
	"math"
	"testing"
)

func TestQuickEntropy(t *testing.T) {
	// 3 lowercase letters: 3 * log2(26)
	want := 3 * math.Log2(26)
	if got := quickEntropy("abc"); math.Abs(got-want) > 1e-9 {
		t.Errorf("quickEntropy(abc) = %f, want %f", got, want)
	}
	if got := quickEntropy(""); got != 0 {
		t.Errorf("empty password should have 0 entropy, got %f", got)
	}
	if quickEntropy("Abc123!x") <= quickEntropy("abcdefgh") {
		t.Error("mixed character classes should have higher entropy than lowercase only")
	}
}

func TestHumanDuration(t *testing.T) {
	cases := []struct {
		seconds float64
		want    string
	}{
		{0.2, "instantly"},
		{30, "30 seconds"},
		{90, "2 minutes"},
		{3600 * 5, "5 hours"},
		{86400 * 3, "3 days"},
		{86400 * 365 * 40, "40 years"},
		{86400 * 365 * 5000, "thousands of years"},
		{86400 * 365 * 5e6, "millions of years"},
		{86400 * 365 * 5e9, "billions of years"},
		{math.Inf(1), "longer than the age of the universe"},
	}
	for _, c := range cases {
		if got := humanDuration(c.seconds); got != c.want {
			t.Errorf("humanDuration(%g) = %q, want %q", c.seconds, got, c.want)
		}
	}
}

func TestCrackTimeGrowsWithEntropy(t *testing.T) {
	if crackTimeSeconds(40) >= crackTimeSeconds(60) {
		t.Error("more entropy must take longer to crack")
	}
	if got := humanDuration(crackTimeSeconds(quickEntropy("abc"))); got != "instantly" {
		t.Errorf("3-letter password should be cracked instantly, got %q", got)
	}
}

func TestBuildReportOfflineHidesPassword(t *testing.T) {
	r := buildReport(7, "correct-horse-battery-staple-9!", false)
	if r.Line != 7 || r.Length != 31 {
		t.Errorf("unexpected report: %+v", r)
	}
	if r.BreachChecked {
		t.Error("offline report must not claim a breach check happened")
	}
}
