package tun2socks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/xxf098/go-tun2socks-build/v2ray"
	vcore "v2ray.com/core"
	vnet "v2ray.com/core/common/net"
	vinbound "v2ray.com/core/features/inbound"
	"v2ray.com/core/infra/conf"
)

const (
	testProxyPort         = uint32(8899)
	testUrl               = "http://www.gstatic.com/generate_204"
	Version5              = 0x05
	AuthMethodNotRequired = 0x00
	SocksCmdConnect       = 0x01
	AddrTypeIPv4          = 0x01
	AddrTypeFQDN          = 0x03
	AddrTypeIPv6          = 0x04
	StatusSucceeded       = 0x00
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

// https://github.com/golang/net/blob/master/internal/socks/client.go
// scoks5 test vmess test
// TODO: error message
func checkServerCredentials(ip string, port uint32) (int64, error) {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	defer conn.Close()
	if err != nil {
		return 0, err
	}
	err = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if err != nil {
		return 0, err
	}
	remoteHost := "www.gstatic.com"
	remotePort := 80
	b := make([]byte, 0, 6+len(remoteHost))
	b = append(b, Version5)
	b = append(b, 1, byte(AuthMethodNotRequired))
	if _, err = conn.Write(b); err != nil {
		return 0, err
	}
	if _, err = io.ReadFull(conn, b[:2]); err != nil {
		return 0, err
	}
	if b[0] != Version5 {
		return 0, errors.New("unexpected protocol version")
	}
	b = b[:0]
	b = append(b, Version5, SocksCmdConnect, 0)
	b = append(b, AddrTypeFQDN)
	b = append(b, byte(len(remoteHost)))
	b = append(b, remoteHost...)
	b = append(b, byte(remotePort>>8), byte(remotePort))
	if _, err = conn.Write(b); err != nil {
		return 0, err
	}
	if _, err = io.ReadFull(conn, b[:10]); err != nil {
		return 0, err
	}
	if b[0] != Version5 {
		return 0, errors.New("unexpected protocol version")
	}
	if b[1] != StatusSucceeded {
		return 0, errors.New("unknown error")
	}
	if b[2] != 0 {
		return 0, errors.New("non-zero reserved field")
	}
	if err = send204Request(&conn, 2*time.Second); err != nil {
		return 0, err
	}
	// timeout then retry
	start := time.Now()
	if err = send204Request(&conn, 1*time.Second); err != nil {
		return 0, err
	}
	elapsed := time.Since(start)
	return elapsed.Milliseconds(), nil
}

func send204Request(conn *net.Conn, timeout time.Duration) error {
	err = (*conn).SetDeadline(time.Now().Add(timeout))
	if err != nil {
		return err
	}
	remoteHost := "www.gstatic.com"
	httpRequest := fmt.Sprintf("GET /generate_204 HTTP/1.1\r\nHost: %s\r\nCache-Control: max-age=90\r\n\r\n", remoteHost)
	if _, err = fmt.Fprintf(*conn, httpRequest); err != nil {
		return err
	}
	buf := make([]byte, 128)
	n, err := (*conn).Read(buf)
	if err != nil && err != io.EOF {
		return err
	}
	httpResponse := string(buf[:n])
	if !strings.HasPrefix(httpResponse, "HTTP/1.1 204 No Content") {
		return fmt.Errorf("error response: %s", httpResponse)
	}
	return nil
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
						Email:    "xxf098@github.com",
						ID:       profile.ID,
						Security: profile.Security,
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
	// TODO: type = "http"
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

	if profile.Net == "h2" {
		transportProtocol := conf.TransportProtocol(profile.Net)
		vmessOutboundDetourConfig.StreamSetting = &conf.StreamConfig{
			Network:      &transportProtocol,
			HTTPSettings: &conf.HTTPConfig{Path: profile.Path},
		}
		if profile.Host != "" {
			hosts := strings.Split(profile.Host, ",")
			vmessOutboundDetourConfig.StreamSetting.HTTPSettings.Host = conf.NewStringList(hosts)
		}
	}

	if profile.Net == "quic" {
		transportProtocol := conf.TransportProtocol(profile.Net)
		vmessOutboundDetourConfig.StreamSetting = &conf.StreamConfig{
			Network:      &transportProtocol,
			QUICSettings: &conf.QUICConfig{Key: profile.Path},
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
		transportProtocol := conf.TransportProtocol(profile.Net)
		mtu := uint32(1350)
		tti := uint32(50)
		upCap := uint32(12)
		downap := uint32(100)
		congestion := false
		readBufferSize := uint32(1)
		writeBufferSize := uint32(1)
		vmessOutboundDetourConfig.StreamSetting = &conf.StreamConfig{
			Network: &transportProtocol,
			KCPSettings: &conf.KCPConfig{
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
		tlsConfig := &conf.TLSConfig{Insecure: true}
		if profile.Host != "" {
			tlsConfig.ServerName = profile.Host
		}
		vmessOutboundDetourConfig.StreamSetting.TLSSettings = tlsConfig
	}
	return vmessOutboundDetourConfig
}

func createFreedomOutboundDetourConfig() conf.OutboundDetourConfig {
	outboundsSettings2, _ := json.Marshal(v2ray.OutboundsSettings{DomainStrategy: "UseIP"})
	outboundsSettingsMsg2 := json.RawMessage(outboundsSettings2)
	return conf.OutboundDetourConfig{
		Protocol: "freedom",
		Tag:      "direct",
		Settings: &outboundsSettingsMsg2,
	}
}

// 0 all
// 1 bypass LAN
// 2 bypass China
// 3 bypass LAN & China
// 4 GFWList
// 5 ChinaList
// >= 6 bypass LAN & China & AD block
// 	0: "Plain", 1: "Regex", 2: "Domain", 3: "Full",
// https://github.com/Loyalsoldier/v2ray-rules-dat
func createRouterConfig(routeMode int) *conf.RouterConfig {
	domainStrategy := "IPIfNonMatch"
	bypassLAN, _ := json.Marshal(v2ray.Rules{
		Type:        "field",
		OutboundTag: "direct",
		IP:          []string{"geoip:private"},
	})
	bypassChinaIP, _ := json.Marshal(v2ray.Rules{
		Type:        "field",
		OutboundTag: "direct",
		IP:          []string{"geoip:cn"},
	})
	bypassChinaSite, _ := json.Marshal(v2ray.Rules{
		Type:        "field",
		OutboundTag: "direct",
		Domain:      []string{"geosite:cn"},
	})
	blockDomain, _ := json.Marshal(v2ray.Rules{
		Type:        "field",
		OutboundTag: "blocked",
		Domain:      v2ray.BlockDomains,
	})
	// blockAd, _ := json.Marshal(v2ray.Rules{
	// 	Type:        "field",
	// 	OutboundTag: "blocked",
	// 	Domain:      []string{"geosite:category-ads-all"},
	// })
	gfwList, _ := json.Marshal(v2ray.Rules{
		Type:        "field",
		OutboundTag: "proxy",
		Domain:      []string{"geosite:geolocation-!cn"},
	})
	chinaListSite, _ := json.Marshal(v2ray.Rules{
		Type:        "field",
		OutboundTag: "proxy",
		Domain:      []string{"geosite:cn"},
	})
	chinaListIP, _ := json.Marshal(v2ray.Rules{
		Type:        "field",
		OutboundTag: "proxy",
		IP:          []string{"geoip:cn"},
	})
	googleAPI, _ := json.Marshal(v2ray.Rules{
		Type:        "field",
		OutboundTag: "proxy",
		Domain:      []string{"domain:googleapis.cn"},
	})
	// all
	rules := []json.RawMessage{}
	if routeMode == 1 {
		rules = []json.RawMessage{
			json.RawMessage(googleAPI),
			json.RawMessage(bypassLAN),
			json.RawMessage(blockDomain),
		}
	}
	if routeMode == 2 {
		rules = []json.RawMessage{
			json.RawMessage(googleAPI),
			json.RawMessage(blockDomain),
			json.RawMessage(bypassChinaSite),
			json.RawMessage(bypassChinaIP),
		}
	}
	if routeMode == 3 {
		rules = []json.RawMessage{
			json.RawMessage(googleAPI),
			json.RawMessage(blockDomain),
			json.RawMessage(bypassLAN),
			json.RawMessage(bypassChinaSite),
			json.RawMessage(bypassChinaIP),
		}
	}
	if routeMode == 4 {
		rules = []json.RawMessage{
			json.RawMessage(googleAPI),
			json.RawMessage(blockDomain),
			json.RawMessage(gfwList),
		}
	}
	if routeMode == 5 {
		rules = []json.RawMessage{
			json.RawMessage(googleAPI),
			json.RawMessage(blockDomain),
			json.RawMessage(chinaListSite),
			json.RawMessage(chinaListIP),
		}
	}
	if routeMode >= 5 {
		rules = []json.RawMessage{
			json.RawMessage(googleAPI),
			json.RawMessage(bypassLAN),
			json.RawMessage(bypassChinaSite),
			json.RawMessage(bypassChinaIP),
			json.RawMessage(blockDomain),
			// json.RawMessage(blockAd),
		}
	}
	return &conf.RouterConfig{
		DomainStrategy: &domainStrategy,
		RuleList:       rules,
	}
}

// remove https://github.com/v2ray/v2ray-core/blob/02b658cd2beb5968818c7ed37388fb348b9b9cb9/app/dns/server.go#L362
func createDNSConfig(routeMode int) *conf.DnsConfig {
	nameServerConfig := []*conf.NameServerConfig{
		&conf.NameServerConfig{
			Address: &conf.Address{vnet.IPAddress([]byte{223, 5, 5, 5})},
			Port:    53,
			// Domains: []string{"geosite:cn"},
		},
		&conf.NameServerConfig{Address: &conf.Address{vnet.IPAddress([]byte{1, 1, 1, 1})}, Port: 53},
	}
	if routeMode == 2 || routeMode == 3 || routeMode == 4 {
		nameServerConfig = []*conf.NameServerConfig{
			&conf.NameServerConfig{Address: &conf.Address{vnet.IPAddress([]byte{1, 1, 1, 1})}, Port: 53},
		}
	}
	return &conf.DnsConfig{
		Hosts:   v2ray.BlockHosts,
		Servers: nameServerConfig,
	}
}
