package dns

import (
	"fmt"
	"testing"
)

func TestLookupIP(t *testing.T) {

	addrs, err := LookupIP("google.com.", "8.8.8.8:53")
	if err != nil {
		t.Error(err)
	}
	for _, addr := range addrs {
		t.Log(fmt.Printf("latency: %s", addr.IP.String()))
	}
}
