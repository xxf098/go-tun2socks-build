package ping

import (
	"fmt"
	"net"
	"time"
)

type PingResult struct {
	latency int64
	err     error
}

func (pingResult PingResult) Get() (int64, error) {
	return pingResult.latency, pingResult.err
}

type TCPPing struct {
	host string
	port int
	done chan PingResult
}

func NewTCPPing(host string, port int) *TCPPing {
	tcpping := TCPPing{
		host: host,
		port: port,
		done: make(chan PingResult),
	}
	return &tcpping
}
func (tcpping TCPPing) Start() <-chan PingResult {
	go func() {
		totalCount, successCount := 0, 0
		latency := int64(0)
		result := PingResult{latency: 0, err: nil}
		for {
			if totalCount >= 2 || successCount >= 2 {
				tcpping.done <- result
				return
			}
			start := time.Now()
			timeout := 1 * time.Second
			if totalCount == 0 {
				timeout = 2 * time.Second
			}
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", tcpping.host, tcpping.port), timeout)
			if err != nil {
				totalCount++
				result = PingResult{latency: 0, err: err}
				continue
			}
			elapsed := time.Since(start)
			latency = elapsed.Milliseconds()
			conn.Close()
			successCount++
			totalCount++
			result = PingResult{latency: latency, err: nil}
		}
	}()
	return tcpping.done
}
