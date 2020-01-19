package tun2socks

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/xxf098/go-tun2socks-build/v2ray"
	vcore "v2ray.com/core"
	vnet "v2ray.com/core/common/net"
	vinbound "v2ray.com/core/features/inbound"
	"v2ray.com/core/infra/conf"
)

func testLatency(proxy string) (int64, error) {
	socksProxyURL, err := url.Parse(proxy)
	if err != nil {
		return 0, err
	}
	socksTransport := &http.Transport{Proxy: http.ProxyURL(socksProxyURL)}
	client := &http.Client{Transport: socksTransport, Timeout: time.Second * 3}
	start := time.Now()
	resp, err := client.Get("https://clients3.google.com/generate_204")
	if err != nil {
		return 0, err
	}
	elapsed := time.Since(start)
	defer resp.Body.Close()
	if err != nil {
		return 0, err
	}
	// fmt.Println(resp.Status)
	// fmt.Println(resp.StatusCode)
	if resp.StatusCode == 204 {
		return elapsed.Milliseconds(), nil
	}
	return 0, newError(resp.Status)
}

func createInboundConfig(proxyPort uint32) (*vcore.InboundHandlerConfig, error) {
	// inboundManager.RemoveHandler(context.Background(), "socks-in")
	// inboundManager.RemoveHandler(context.Background(), "http-in")
	inboundsSettings, _ := json.Marshal(v2ray.InboundsSettings{
		Auth: "noauth",
		IP:   "127.0.0.1",
		UDP:  true,
	})
	inboundsSettingsMsg := json.RawMessage(inboundsSettings)
	inboundDetourConfig := conf.InboundDetourConfig{
		Tag:       "socks-in",
		Protocol:  "socks",
		PortRange: &conf.PortRange{From: proxyPort, To: proxyPort},
		ListenOn:  &conf.Address{vnet.IPAddress([]byte{127, 0, 0, 1})},
		Settings:  &inboundsSettingsMsg,
	}
	return inboundDetourConfig.Build()
}

func addInboundHandler(server *vcore.Instance) (string, error) {
	if inboundManager := server.GetFeature(vinbound.ManagerType()).(vinbound.Manager); inboundManager != nil {
		if _, err := inboundManager.GetHandler(context.Background(), "socks-in"); err == nil {
			if err := inboundManager.RemoveHandler(context.Background(), "socks-in"); err != nil {
				return "", err
			}
		}
	}
	const proxyPort = 8899
	inboundConfig, err := createInboundConfig(proxyPort)
	if err != nil {
		return "", err
	}
	err = vcore.AddInboundHandler(server, inboundConfig)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("socks5://127.0.0.1:%d", proxyPort), nil
}
