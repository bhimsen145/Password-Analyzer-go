package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
const (
	passwordPrefix = "5BAA6"
	passwordSuffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
)

func fakeAPI(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only the 5-character prefix may ever be requested.
		if r.URL.Path != "/range/"+passwordPrefix {
			t.Errorf("unexpected request path %q (full hash must never be sent)", r.URL.Path)
		}
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	old := breachAPIBase
	breachAPIBase = srv.URL + "/range/"
	t.Cleanup(func() {
		breachAPIBase = old
		srv.Close()
	})
	return srv
}

func TestCheckBreachFound(t *testing.T) {
	fakeAPI(t, 200, "0000000000000000000000000000000000A:2\r\n"+passwordSuffix+":10000000\r\n")
	count, err := checkBreach("password")
	if err != nil {
		t.Fatal(err)
	}
	if count != 10000000 {
		t.Errorf("got %d, want 10000000", count)
	}
}

func TestCheckBreachNotFound(t *testing.T) {
	fakeAPI(t, 200, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:5\r\n")
	count, err := checkBreach("password")
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("got %d, want 0", count)
	}
}

func TestCheckBreachPaddedEntryIsZero(t *testing.T) {
	fakeAPI(t, 200, passwordSuffix+":0\r\n")
	count, _ := checkBreach("password")
	if count != 0 {
		t.Errorf("padded entry should count as 0, got %d", count)
	}
}

func TestCheckBreachServerError(t *testing.T) {
	fakeAPI(t, 503, "")
	if _, err := checkBreach("password"); err == nil {
		t.Error("expected an error for HTTP 503")
	}
}

func TestFormatCount(t *testing.T) {
	cases := map[int]string{0: "0", 999: "999", 1000: "1,000", 12345: "12,345", 10000000: "10,000,000"}
	for in, want := range cases {
		if got := formatCount(in); got != want {
			t.Errorf("formatCount(%d) = %q, want %q", in, got, want)
		}
	}
}
