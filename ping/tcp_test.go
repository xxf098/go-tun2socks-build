package ping

import (
	"fmt"
	"testing"
)

func TestGenerateVmessConfig(t *testing.T) {
	tcpping := NewTCPPing("167.179.109.28", 80)
	latency := <-tcpping.Start()
	t.Log(fmt.Printf("latency: %d", latency))
}
