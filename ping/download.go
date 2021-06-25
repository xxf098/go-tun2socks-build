package ping

import (
	"context"
	"fmt"
	"time"

	"github.com/xxf098/lite-proxy/download"
	"github.com/xxf098/lite-proxy/web"
	"github.com/xxf098/lite-proxy/web/render"
)

func testAll(ctx context.Context, links []string, max int, trafficChan chan<- int64) (chan render.Node, error) {

	p := web.ProfileTest{
		Writer:      nil,
		MessageType: web.ALLTEST,
		Links:       links,
		Options: &web.ProfileTestOptions{
			GroupName:     "Default",
			SpeedTestMode: "all",
			PingMethod:    "googleping",
			SortMethod:    "none",
			Concurrency:   max,
			TestMode:      2,
			Timeout:       15 * time.Second,
			Language:      "en",
			FontSize:      24,
		},
	}

	return p.TestAll(ctx, links, max, trafficChan)
}

func RenderDownloadLinksSpeed(links []string, max int, fontPath string, pngPath string, language string, urlGroup string, testInfoChan chan<- TestResult) error {
	defer func() {
		if testInfoChan != nil {
			close(testInfoChan)
		}
	}()
	ctx := context.Background()
	trafficChan := make(chan int64)
	var start = time.Now()
	nodeChan, err := testAll(ctx, links, max, trafficChan)
	if err != nil {
		return err
	}
	count := 0
	successCount := 0
	linkCount := len(links)
	var sum int64
	nodes := make(render.Nodes, linkCount)
	for count < linkCount {
		select {
		case traffic := <-trafficChan:
			if traffic > 0 {
				sum += traffic
				fmt.Printf("traffic: %s\n", download.ByteCountIECTrim(sum))
			}
			testResult := TestResult{
				Result:   traffic,
				Protocol: PROTOCOL_TRAFFIC,
			}
			if testInfoChan != nil {
				testInfoChan <- testResult
			}
		case node := <-nodeChan:
			node.Group = urlGroup
			nodes[node.Id] = node
			if node.IsOk {
				successCount += 1
			}
			testResult := TestResult{
				Result:   node.MaxSpeed,
				Index:    node.Id,
				Protocol: PROTOCOL_SPEED,
			}
			if testInfoChan != nil {
				testInfoChan <- testResult
			}
			fmt.Printf("index: %d, elapse: %s, avg: %s, max: %s\n", node.Id, node.Ping, download.ByteCountIEC(node.AvgSpeed), download.ByteCountIEC(node.MaxSpeed))
			count += 1
		}
	}
	close(nodeChan)

	duration := web.FormatDuration(time.Since(start))
	options := render.NewTableOptions(40, 30, 0.5, 0.5, 24, 0.5, fontPath, language, "original", "Asia/Shanghai", []byte{})
	nodes.Sort("rspeed")
	table, err := render.NewTableWithOption(nodes, &options)
	if err != nil {
		return err
	}
	msg := table.FormatTraffic(download.ByteCountIECTrim(sum), duration, fmt.Sprintf("%d/%d", successCount, linkCount))
	table.Draw(pngPath, msg)
	return nil
}

func RenderDownloadLinksSpeedAndroid(links []string, max int, fontPath string, pngPath string, language string, urlGroup string) <-chan TestResult {
	testInfoChan := make(chan TestResult)
	go func(c chan<- TestResult) {
		RenderDownloadLinksSpeed(links, max, fontPath, pngPath, language, urlGroup, c)
	}(testInfoChan)
	return testInfoChan
}
