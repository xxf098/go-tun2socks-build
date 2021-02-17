package ping

import "sync"

type TestResult struct {
	Result   int64
	Server   string
	Port     int
	Index    int
	Err      error
	Protocol string
}

type RunFunc func(int, string, chan<- TestResult) (error, bool)

func BatchTestLinks(links []string, max int, runFuncs []RunFunc) <-chan TestResult {
	if max < 1 {
		max = 5
	}
	resultChan := make(chan TestResult)
	go func(c chan<- TestResult) {
		maxChan := make(chan bool, max)
		var wg sync.WaitGroup
		for i, link := range links {
			wg.Add(1)
			go func(index int, link string) {
				defer wg.Done()
				maxChan <- true
				for _, runFunc := range runFuncs {
					_, next := runFunc(index, link, c)
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

// func PingLinksLatency(links []string, max int, runPings []RunPing) <-chan LatencyResult {
// 	runs := append([]RunPing{RunVmess, RunTrojan}, runPings...)
// 	return PingLinksLatencyRun(links, max, runs)
// }
