package ping

import "sync"

type LatencyResult struct {
	Elapsed  int64
	Server   string
	Port     int
	Index    int
	Err      error
	Protocol string
}

type RunPing func(int, string, chan<- LatencyResult) (error, bool)

func PingLinksLatencyRun(links []string, max int, runPings []RunPing) <-chan LatencyResult {
	if max < 1 {
		max = 5
	}
	resultChan := make(chan LatencyResult)
	go func(c chan<- LatencyResult) {
		maxChan := make(chan bool, max)
		var wg sync.WaitGroup
		for i, link := range links {
			wg.Add(1)
			go func(index int, link string) {
				defer wg.Done()
				maxChan <- true
				for _, runPing := range runPings {
					_, next := runPing(index, link, c)
					if !next {
						break
					}
				}
				<-maxChan
			}(i, link)
		}
		wg.Wait()
		close(c)
	}(resultChan)
	return resultChan
}

func PingLinksLatency(links []string, max int, runPings []RunPing) <-chan LatencyResult {
	runs := append([]RunPing{RunVmess, RunTrojan}, runPings...)
	return PingLinksLatencyRun(links, max, runs)
}
