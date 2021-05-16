package ping

import (
	"context"
	"time"

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

func RenderDownloadLinksSpeed(links []string, max int) (<-chan render.Node, error) {
	ctx := context.Background()
	return testAll(ctx, links, max, nil)
}
