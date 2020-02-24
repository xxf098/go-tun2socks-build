package tun2socks

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/xxf098/go-tun2socks-build/v2ray"
	vcore "v2ray.com/core"
	vnet "v2ray.com/core/common/net"
	vinbound "v2ray.com/core/features/inbound"
	vconf "v2ray.com/core/infra/conf"
)

const (
	testProxyPort = 8899
	testUrl       = "https://www.google.com/generate_204"
)

func testLatency(proxy string) (int64, error) {
	socksProxyURL, err := url.Parse(proxy)
	if err != nil {
		return 0, err
	}
	socksTransport := &http.Transport{Proxy: http.ProxyURL(socksProxyURL)}
	client := &http.Client{Transport: socksTransport, Timeout: time.Second * 3}
	resp, err := client.Get(testUrl)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if err != nil {
		return 0, err
	}
	// fmt.Println(resp.Status)
	// fmt.Println(resp.StatusCode)
	if resp.StatusCode == 204 {
		start := time.Now()
		resp1, err := client.Get(testUrl)
		elapsed := time.Since(start)
		if err != nil {
			return 0, err
		}
		defer resp1.Body.Close()
		if resp1.StatusCode == 204 {
			return elapsed.Milliseconds(), nil
		}
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

func createInboundDetourConfig(proxyPort uint32) vconf.InboundDetourConfig {
	// inboundManager.RemoveHandler(context.Background(), "socks-in")
	// inboundManager.RemoveHandler(context.Background(), "http-in")
	inboundsSettings, _ := json.Marshal(v2ray.InboundsSettings{
		Auth: "noauth",
		IP:   "127.0.0.1",
		UDP:  true,
	})
	inboundsSettingsMsg := json.RawMessage(inboundsSettings)
	inboundDetourConfig := vconf.InboundDetourConfig{
		Tag:       "socks-in",
		Protocol:  "socks",
		PortRange: &vconf.PortRange{From: proxyPort, To: proxyPort},
		ListenOn:  &vconf.Address{vnet.IPAddress([]byte{127, 0, 0, 1})},
		Settings:  &inboundsSettingsMsg,
	}
	return inboundDetourConfig
}

func createVmessOutboundDetourConfig(profile *Vmess) vconf.OutboundDetourConfig {
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
	vmessOutboundDetourConfig := vconf.OutboundDetourConfig{
		Protocol:      "vmess",
		Tag:           "proxy",
		MuxSettings:   &vconf.MuxConfig{Enabled: true, Concurrency: 16},
		Settings:      &outboundsSettingsMsg1,
		StreamSetting: &vconf.StreamConfig{},
	}
	if profile.Net == "ws" {
		transportProtocol := vconf.TransportProtocol(profile.Net)
		vmessOutboundDetourConfig.StreamSetting = &vconf.StreamConfig{
			Network:    &transportProtocol,
			WSSettings: &vconf.WebSocketConfig{Path: profile.Path},
		}
		if profile.Host != "" {
			vmessOutboundDetourConfig.StreamSetting.WSSettings.Headers =
				map[string]string{"Host": profile.Host}
		}
	}

	if profile.Net == "h2" {
		transportProtocol := vconf.TransportProtocol(profile.Net)
		vmessOutboundDetourConfig.StreamSetting = &vconf.StreamConfig{
			Network:      &transportProtocol,
			HTTPSettings: &vconf.HTTPConfig{Path: profile.Path},
		}
		if profile.Host != "" {
			hosts := strings.Split(profile.Host, ",")
			vmessOutboundDetourConfig.StreamSetting.HTTPSettings.Host = vconf.NewStringList(hosts)
		}
	}

	if profile.Net == "quic" {
		transportProtocol := vconf.TransportProtocol(profile.Net)
		vmessOutboundDetourConfig.StreamSetting = &vconf.StreamConfig{
			Network:      &transportProtocol,
			QUICSettings: &vconf.QUICConfig{Key: profile.Path},
		}
		if profile.Host != "" {
			vmessOutboundDetourConfig.StreamSetting.QUICSettings.Security = profile.Host
		}
		if profile.Type != "" {
			header, _ := json.Marshal(v2ray.QUICSettingsHeader{Type: profile.Type})
			vmessOutboundDetourConfig.StreamSetting.QUICSettings.Header = json.RawMessage(header)
		}
	}

	if profile.Net == "kcp" {
		transportProtocol := vconf.TransportProtocol(profile.Net)
		mtu := uint32(1350)
		tti := uint32(50)
		upCap := uint32(12)
		downap := uint32(100)
		congestion := false
		readBufferSize := uint32(1)
		writeBufferSize := uint32(1)
		vmessOutboundDetourConfig.StreamSetting = &vconf.StreamConfig{
			Network: &transportProtocol,
			KCPSettings: &vconf.KCPConfig{
				Mtu:             &mtu,
				Tti:             &tti,
				UpCap:           &upCap,
				DownCap:         &downap,
				Congestion:      &congestion,
				ReadBufferSize:  &readBufferSize,
				WriteBufferSize: &writeBufferSize,
			},
		}
		if profile.Type != "" {
			header, _ := json.Marshal(v2ray.KCPSettingsHeader{Type: profile.Type})
			vmessOutboundDetourConfig.StreamSetting.KCPSettings.HeaderConfig = json.RawMessage(header)
		}
	}

	if profile.TLS == "tls" {
		vmessOutboundDetourConfig.StreamSetting.Security = profile.TLS
		tlsConfig := &vconf.TLSConfig{Insecure: true}
		if profile.Host != "" {
			tlsConfig.ServerName = profile.Host
		}
		vmessOutboundDetourConfig.StreamSetting.TLSSettings = tlsConfig
	}
	return vmessOutboundDetourConfig
}

func createFreedomOutboundDetourConfig() vconf.OutboundDetourConfig {
	outboundsSettings2, _ := json.Marshal(v2ray.OutboundsSettings{DomainStrategy: "UseIP"})
	outboundsSettingsMsg2 := json.RawMessage(outboundsSettings2)
	return vconf.OutboundDetourConfig{
		Protocol: "freedom",
		Tag:      "direct",
		Settings: &outboundsSettingsMsg2,
	}
}

func createRouterConfig() *vconf.RouterConfig {
	domainStrategy := "IPIfNonMatch"
	rule1, _ := json.Marshal(v2ray.Rules{
		Type:        "field",
		OutboundTag: "direct",
		IP:          []string{"geoip:private", "geoip:cn"},
	})
	rule2, _ := json.Marshal(v2ray.Rules{
		Type:        "field",
		OutboundTag: "direct",
		Domain:      []string{"geosite:cn"},
	})
	rule3, _ := json.Marshal(v2ray.Rules{
		Type:        "field",
		OutboundTag: "blocked",
		Domain:      v2ray.BlockDomains,
	})
	return &vconf.RouterConfig{
		DomainStrategy: &domainStrategy,
		RuleList:       []json.RawMessage{json.RawMessage(rule1), json.RawMessage(rule2), json.RawMessage(rule3)},
	}
}

func createDNSConfig() *vconf.DnsConfig {
	return &vconf.DnsConfig{
		Servers: []*vconf.NameServerConfig{
			&vconf.NameServerConfig{
				Address: &vconf.Address{vnet.IPAddress([]byte{223, 5, 5, 5})},
				Port:    53,
				// Domains: []string{"geosite:cn"},
			},
			// &vconf.NameServerConfig{Address: &vconf.Address{vnet.IPAddress([]byte{8, 8, 8, 8})}, Port: 53},
			// &vconf.NameServerConfig{Address: &vconf.Address{vnet.IPAddress([]byte{1, 1, 1, 1})}, Port: 53},
			&vconf.NameServerConfig{Address: &vconf.Address{vnet.IPAddress([]byte{127, 0, 0, 1})}, Port: 53},
			// &vconf.NameServerConfig{Address: &vconf.Address{vnet.DomainAddress("localhost")}, Port: 53},
		},
		Hosts: v2ray.BlockHosts,
	}
}
