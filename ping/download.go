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
		Conn:        nil,
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

func RenderDownloadLinksSpeed(links []string, max int, fontPath string, pngPath string) error {
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
	nodes := make([]render.Node, linkCount)
	for count < linkCount {
		select {
		case traffic := <-trafficChan:
			if traffic > 0 {
				sum += traffic
				fmt.Printf("traffic: %s\n", download.ByteCountIECTrim(sum))
			}
		case node := <-nodeChan:
			nodes[node.Id] = node
			if node.IsOk {
				successCount += 1
			}
			fmt.Printf("index: %d, elapse: %s, avg: %s, max: %s\n", node.Id, node.Ping, download.ByteCountIEC(node.AvgSpeed), download.ByteCountIEC(node.MaxSpeed))
			count += 1
		}
	}
	close(nodeChan)
	duration := web.FormatDuration(time.Since(start))
	options := render.NewTableOptions(40, 30, 0.5, 0.5, 24, 0.5, fontPath, "en")
	table, err := render.NewTableWithOption(nodes, &options)
	if err != nil {
		return err
	}
	msg := table.FormatTraffic(download.ByteCountIECTrim(sum), duration, fmt.Sprintf("%d/%d", successCount, linkCount))
	table.Draw(pngPath, msg)
	return nil
}
