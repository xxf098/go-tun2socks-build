package ping

import (
	"sync"
	"time"

	"github.com/xxf098/lite-proxy/config"
	"github.com/xxf098/lite-proxy/download"
	"github.com/xxf098/lite-proxy/request"
)

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

func runVmess(index int, link string, c chan<- TestResult) (error, bool) {
	option, err := config.VmessLinkToVmessConfigIP(link, false)
	if err != nil {
		return err, true
	}
	n := option.Net
	if n != "" && n != "tcp" && n != "ws" && n != "http" && n != "h2" {
		return nil, true
	}
	return runLite(index, link, "vmess", c)
}

func runTrojan(index int, link string, c chan<- TestResult) (error, bool) {
	_, err := config.TrojanLinkToTrojanOption(link)
	if err != nil {
		return err, true
	}
	return runLite(index, link, "trojan", c)
}

func runShadowSocks(index int, link string, c chan<- TestResult) (error, bool) {
	_, err := config.SSLinkToSSOption(link)
	if err != nil {
		return err, true
	}
	return runLite(index, link, "ss", c)
}

func runLite(index int, link string, protocol string, c chan<- TestResult) (error, bool) {
	elapse, err := request.PingLink(link, 1)
	result := TestResult{
		Result:   elapse,
		Index:    index,
		Err:      err,
		Protocol: protocol,
	}
	c <- result
	return err, false
}

func PingLinksLatency(links []string, max int, runPings []RunFunc) <-chan TestResult {
	runs := append([]RunFunc{runVmess, runTrojan, runShadowSocks}, runPings...)
	return BatchTestLinks(links, max, runs)
}

func runDownload(index int, link string, c chan<- TestResult) (error, bool) {
	speed, err := download.Download(link, 15*time.Second, 15*time.Second, nil)
	result := TestResult{
		Result:   speed,
		Index:    index,
		Err:      err,
		Protocol: "download",
	}
	c <- result
	return err, false
}

func DownloadLinksSpeed(links []string, max int) <-chan TestResult {
	runs := append([]RunFunc{runDownload})
	return BatchTestLinks(links, max, runs)
}
