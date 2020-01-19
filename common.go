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

const (
	testProxyPort = 8899
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

func addInboundHandler(server *vcore.Instance) (string, error) {
	if inboundManager := server.GetFeature(vinbound.ManagerType()).(vinbound.Manager); inboundManager != nil {
		if _, err := inboundManager.GetHandler(context.Background(), "socks-in"); err == nil {
			if err := inboundManager.RemoveHandler(context.Background(), "socks-in"); err != nil {
				return "", err
			}
		}
	}
	inboundDetourConfig := createInboundDetourConfig(testProxyPort)
	inboundConfig, err := inboundDetourConfig.Build()
	if err != nil {
		return "", err
	}
	err = vcore.AddInboundHandler(server, inboundConfig)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("socks5://127.0.0.1:%d", testProxyPort), nil
}

func createInboundDetourConfig(proxyPort uint32) conf.InboundDetourConfig {
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
	return inboundDetourConfig
}

func createVmessOutboundDetourConfig(profile *Vmess) conf.OutboundDetourConfig {
	outboundsSettings1, _ := json.Marshal(v2ray.OutboundsSettings{
		Vnext: []v2ray.Vnext{
			v2ray.Vnext{
				Address: profile.Add,
				Port:    profile.Port,
				Users: []v2ray.Users{
					v2ray.Users{
						AlterID:  profile.Aid,
						Email:    "v2ray@email.com",
						ID:       profile.ID,
						Security: "auto",
					},
				},
			},
		},
	})
	outboundsSettingsMsg1 := json.RawMessage(outboundsSettings1)
	vmessOutboundDetourConfig := conf.OutboundDetourConfig{
		Protocol:      "vmess",
		Tag:           "proxy",
		MuxSettings:   &conf.MuxConfig{Enabled: true, Concurrency: 16},
		Settings:      &outboundsSettingsMsg1,
		StreamSetting: &conf.StreamConfig{},
	}
	if profile.Net == "ws" {
		transportProtocol := conf.TransportProtocol(profile.Net)
		vmessOutboundDetourConfig.StreamSetting = &conf.StreamConfig{
			Network:    &transportProtocol,
			WSSettings: &conf.WebSocketConfig{Path: profile.Path},
		}
		if profile.Host != "" {
			vmessOutboundDetourConfig.StreamSetting.WSSettings.Headers =
				map[string]string{"Host": profile.Host}
		}
	}
	if profile.TLS == "tls" {
		vmessOutboundDetourConfig.StreamSetting.Security = profile.TLS
		vmessOutboundDetourConfig.StreamSetting.TLSSettings = &conf.TLSConfig{Insecure: true}
	}
	return vmessOutboundDetourConfig
}
