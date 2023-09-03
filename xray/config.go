package xray

import (
	"encoding/json"
	"strings"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xxf098/go-tun2socks-build/features"
	"github.com/xxf098/go-tun2socks-build/settings"
	"github.com/xxf098/go-tun2socks-build/v2ray"
)

var localhost = conf.NewHostAddress(&conf.Address{net.IPAddress([]byte{0, 0, 0, 0})}, nil)
var googleapis = conf.NewHostAddress(&conf.Address{net.DomainAddress("googleapis.com")}, nil)

var BlockHosts = map[string]*conf.HostAddress{
	// "domain:umeng.com": localhost,
	// "domain:baidu.com":       localhost,
	// "domain:sogou.com":       localhost,
	"domain:doubleclick.net": localhost,
	// "domain:byteimg.com":     localhost,
	// "domain:ixigua.com":      localhost,
	// "domain:snssdk.com":      localhost,
	// "domain:uc.com":          localhost,
	// "domain:uc.cn":           localhost,
	// "domain:umengcloud.com": localhost,
	// "keyword:baidustatic":    localhost,
	"keyword:auspiciousvp": localhost,
	"domain:cnzz.com":      localhost,
	// "domain:toutiaopage.com": localhost,
	// "domain:douyin.com":      localhost,
	// "domain:bdstatic.com":    localhost,
	// "domain:360.cn":       localhost,
	// "domain:umtrack.com":  localhost,
	// "domain:umsns.com":    localhost,
	// "domain:qhupdate.com": localhost,
	// "domain:qhimg.com":    localhost,
	"at3.doubanio.com":     localhost,
	"p.pinduoduo.com":      localhost,
	"pos.baidu.com":        localhost,
	"hm.baidu.com":         localhost,
	"cpro.baidu.com":       localhost,
	"domain:googleapis.cn": googleapis,
}

func createDNSConfig(routeMode int, dnsConf string) *conf.DNSConfig {
	// nameServerConfig := []*conf.NameServerConfig{
	// 	&conf.NameServerConfig{
	// 		Address: &conf.Address{vnet.IPAddress([]byte{223, 5, 5, 5})},
	// 		Port:    53,
	// 		// Domains: []string{"geosite:cn"},
	// 	},
	// 	&conf.NameServerConfig{Address: &conf.Address{vnet.IPAddress([]byte{1, 1, 1, 1})}, Port: 53},
	// }
	// if routeMode == 2 || routeMode == 3 || routeMode == 4 {
	// 	nameServerConfig = []*conf.NameServerConfig{
	// 		&conf.NameServerConfig{Address: &conf.Address{vnet.IPAddress([]byte{1, 1, 1, 1})}, Port: 53},
	// 	}
	// }
	dns := strings.Split(dnsConf, ",")
	nameServerConfig := []*conf.NameServerConfig{}
	if routeMode == 2 || routeMode == 3 || routeMode == 4 {
		for i := len(dns) - 1; i >= 0; i-- {
			if newConfig := toNameServerConfig(dns[i]); newConfig != nil {
				if i == 1 {
					newConfig.Domains = []string{"geosite:cn"}
				}
				nameServerConfig = append(nameServerConfig, newConfig)
			}
		}
	} else {
		if newConfig := toNameServerConfig(dns[0]); newConfig != nil {
			nameServerConfig = append(nameServerConfig, newConfig)
		}
	}
	return &conf.DNSConfig{
		Hosts:   &conf.HostsWrapper{Hosts: BlockHosts},
		Servers: nameServerConfig,
	}
}

// 0 all
// 1 bypass LAN
// 2 bypass China
// 3 bypass LAN & China
// 4 GFWList
// 5 ChinaList
// >= 6 bypass LAN & China & AD block
//
//	0: "Plain", 1: "Regex", 2: "Domain", 3: "Full",
//
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
	directDomains, _ := json.Marshal(v2ray.Rules{
		Type:        "field",
		OutboundTag: "direct",
		Domain:      v2ray.DirectDomains,
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
	gfwListIP, _ := json.Marshal(v2ray.Rules{
		Type:        "field",
		OutboundTag: "proxy",
		IP: []string{
			"8.8.8.8/32",
			"8.8.4.4/32",
			"1.1.1.1/32",
			"1.0.0.1/32",
			"149.154.160.0/22",
			"149.154.164.0/22",
			"91.108.4.0/22",
			"91.108.56.0/22",
			"91.108.8.0/22",
			"95.161.64.0/20",
		},
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
		Domain:      []string{"domain:googleapis.cn", "domain:gstatic.com", "domain:ampproject.org", "domain:google.com.hk"},
	})
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
			json.RawMessage(gfwList),
			json.RawMessage(bypassChinaIP),
		}
	}
	if routeMode == 3 {
		rules = []json.RawMessage{
			json.RawMessage(googleAPI),
			json.RawMessage(blockDomain),
			json.RawMessage(bypassLAN),
			json.RawMessage(directDomains),
			json.RawMessage(bypassChinaSite),
			json.RawMessage(gfwList), // sniff
			json.RawMessage(bypassChinaIP),
		}
	}
	if routeMode == 4 {
		rules = []json.RawMessage{
			json.RawMessage(googleAPI),
			json.RawMessage(blockDomain),
			json.RawMessage(gfwListIP),
			json.RawMessage(gfwList),
		}
	}
	if routeMode == 5 {
		rules = []json.RawMessage{
			// json.RawMessage(googleAPI),
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

func configVmessTransport(profile *features.Vmess, outboundsSettingsMsg1 json.RawMessage) conf.OutboundDetourConfig {
	muxEnabled := false
	if profile.VmessOptions.Mux > 0 {
		muxEnabled = true
	} else {
		profile.VmessOptions.Mux = -1
	}
	tcp := conf.TransportProtocol("tcp")
	streamSetting := &conf.StreamConfig{
		Network:  &tcp,
		Security: "",
	}
	if profile.Protocol == v2ray.VLESS {
		tcpHeader, _ := json.Marshal(v2ray.TcpHeader{Type: profile.Type})
		tcpHeaderMsg := json.RawMessage(tcpHeader)
		tcpSetting := &conf.TCPConfig{
			HeaderConfig: tcpHeaderMsg,
		}
		streamSetting.TCPSettings = tcpSetting
	}
	vmessOutboundDetourConfig := conf.OutboundDetourConfig{
		Protocol:      "vmess",
		Tag:           "proxy",
		MuxSettings:   &conf.MuxConfig{Enabled: muxEnabled, Concurrency: int16(profile.VmessOptions.Mux)},
		Settings:      &outboundsSettingsMsg1,
		StreamSetting: streamSetting,
	}
	if profile.Protocol == v2ray.VLESS {
		vmessOutboundDetourConfig.Protocol = "vless"
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

	// tcp带http伪装
	if profile.Net == "tcp" && profile.Type == "http" {
		transportProtocol := conf.TransportProtocol(profile.Net)
		tcpSettingsHeader := v2ray.TCPSettingsHeader{
			Type: profile.Type,
			TCPSettingsRequest: v2ray.TCPSettingsRequest{
				Version: "1.1",
				Method:  "GET",
				Path:    []string{profile.Path}, // TODO: split by ","
				Headers: v2ray.HTTPHeaders{
					UserAgent:      []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36"},
					AcceptEncoding: []string{"gzip, deflate"},
					Connection:     "keep-alive",
					Pragma:         "no-cache",
					Host:           []string{profile.Host}, // TODO: split by ","
				},
			},
		}
		header, _ := json.Marshal(tcpSettingsHeader)
		vmessOutboundDetourConfig.StreamSetting = &conf.StreamConfig{
			Network:  &transportProtocol,
			Security: profile.TLS,
			TCPSettings: &conf.TCPConfig{
				HeaderConfig: json.RawMessage(header),
			},
		}
	}

	if profile.TLS == "tls" {
		vmessOutboundDetourConfig.StreamSetting.Security = profile.TLS
		tlsConfig := &conf.TLSConfig{Insecure: profile.AllowInsecure}
		if profile.Host != "" {
			tlsConfig.ServerName = profile.Host
		}
		if profile.SNI != "" {
			tlsConfig.ServerName = profile.SNI
		}
		vmessOutboundDetourConfig.StreamSetting.TLSSettings = tlsConfig
	}
	return vmessOutboundDetourConfig
}

func createVlessOutboundDetourConfig(profile *features.Vmess) conf.OutboundDetourConfig {
	security := profile.Security
	if len(security) < 1 {
		security = "auto"
	}
	encryption := profile.Encryption
	if len(encryption) < 1 {
		encryption = "none"
	}
	outboundsSettings1, _ := json.Marshal(v2ray.VlessOutboundsSettings{
		Vnext: []v2ray.Vlessnext{
			{
				Address: profile.Add,
				Port:    profile.Port,
				Users: []v2ray.VlessUser{
					{
						Encryption: encryption,
						Flow:       profile.Flow,
						ID:         profile.ID,
						Level:      8,
						Security:   security,
					},
				},
			},
		},
	})
	outboundsSettingsMsg := json.RawMessage(outboundsSettings1)
	return configVmessTransport(profile, outboundsSettingsMsg)
}

func createVmessOutboundDetourConfig(profile *features.Vmess) conf.OutboundDetourConfig {
	outboundsSettings1, _ := json.Marshal(v2ray.OutboundsSettings{
		Vnext: []v2ray.Vnext{
			{
				Address: profile.Add,
				Port:    profile.Port,
				Users: []v2ray.Users{
					{
						AlterID:  profile.Aid,
						Email:    "xxf098@github.com",
						ID:       profile.ID,
						Level:    8,
						Security: profile.Security,
					},
				},
			},
		},
	})
	outboundsSettingsMsg1 := json.RawMessage(outboundsSettings1)
	return configVmessTransport(profile, outboundsSettingsMsg1)
}

func createTrojanOutboundDetourConfig(profile *features.Vmess) conf.OutboundDetourConfig {
	config := profile.Trojan
	// outboundsSettings, _ := json.Marshal(trojan.OutboundsSettings{
	// 	Address:    config.Add,
	// 	Password:   config.Password,
	// 	Port:       config.Port,
	// 	ServerName: config.SNI,
	// 	SkipVerify: config.SkipCertVerify,
	// })
	outboundsSettings, _ := json.Marshal(settings.TrojanOutboundsSettings{
		Servers: []*settings.TrojanServerTarget{
			{
				Address:  config.Add,
				Email:    "xxf098@github.com",
				Level:    8,
				Password: config.Password,
				Port:     uint16(config.Port),
			},
		},
	})
	outboundsSettingsMsg := json.RawMessage(outboundsSettings)
	transportProtocol := conf.TransportProtocol("tcp")
	trojanOutboundDetourConfig := conf.OutboundDetourConfig{
		Protocol: "trojan",
		Tag:      "proxy",
		Settings: &outboundsSettingsMsg,
		StreamSetting: &conf.StreamConfig{
			Security: "tls",
			Network:  &transportProtocol,
			TLSSettings: &conf.TLSConfig{
				Insecure:   config.SkipCertVerify,
				ServerName: config.SNI,
			},
		},
	}
	return trojanOutboundDetourConfig
}

func createShadowsocksOutboundDetourConfig(profile *features.Vmess) conf.OutboundDetourConfig {
	config := profile.Shadowsocks
	outboundsSettings, _ := json.Marshal(settings.ShadowsocksOutboundsSettings{
		Servers: []*settings.ShadowsocksServerTarget{
			{
				Address:  config.Add,
				Method:   config.Method,
				Email:    "xxf098@github.com",
				Level:    0,
				OTA:      false,
				Password: config.Password,
				Port:     uint16(config.Port),
			},
		},
	})
	outboundsSettingsMsg := json.RawMessage(outboundsSettings)
	shadowsocksOutboundDetourConfig := conf.OutboundDetourConfig{
		Protocol: "shadowsocks",
		Tag:      "proxy",
		Settings: &outboundsSettingsMsg,
	}
	return shadowsocksOutboundDetourConfig
}

func getProxyOutboundDetourConfig(profile *features.Vmess) conf.OutboundDetourConfig {
	proxyOutboundConfig := conf.OutboundDetourConfig{}
	if profile.Protocol == v2ray.VMESS {
		proxyOutboundConfig = createVmessOutboundDetourConfig(profile)
	}
	if profile.Protocol == v2ray.TROJAN {
		proxyOutboundConfig = createTrojanOutboundDetourConfig(profile)
	}
	if profile.Protocol == v2ray.SHADOWSOCKS {
		proxyOutboundConfig = createShadowsocksOutboundDetourConfig(profile)
	}
	if profile.Protocol == v2ray.VLESS {
		proxyOutboundConfig = createVlessOutboundDetourConfig(profile)
	}
	return proxyOutboundConfig
}

func createFreedomOutboundDetourConfig(useIPv6 bool) conf.OutboundDetourConfig {
	domainStrategy := "useipv4"
	if useIPv6 {
		domainStrategy = "useip"
	}
	outboundsSettings2, _ := json.Marshal(v2ray.OutboundsSettings{DomainStrategy: domainStrategy})
	outboundsSettingsMsg2 := json.RawMessage(outboundsSettings2)
	return conf.OutboundDetourConfig{
		Protocol: "freedom",
		Tag:      "direct",
		Settings: &outboundsSettingsMsg2,
	}
}

func creatPolicyConfig() *conf.PolicyConfig {
	handshake := uint32(4)
	connIdle := uint32(300)
	downlinkOnly := uint32(1)
	uplinkOnly := uint32(1)
	return &conf.PolicyConfig{
		Levels: map[uint32]*conf.Policy{
			8: {
				ConnectionIdle: &connIdle,
				DownlinkOnly:   &downlinkOnly,
				Handshake:      &handshake,
				UplinkOnly:     &uplinkOnly,
			},
		},
		System: &conf.SystemPolicy{
			StatsOutboundUplink:   true,
			StatsOutboundDownlink: true,
		},
	}
}

func LoadXVmessConfig(profile *features.Vmess) (*conf.Config, error) {
	jsonConfig := &conf.Config{}
	jsonConfig.LogConfig = &conf.LogConfig{
		// AccessLog: "",
		// ErrorLog:  "",
		LogLevel: profile.Loglevel,
	}
	jsonConfig.DNSConfig = createDNSConfig(profile.RouteMode, profile.DNS)
	jsonConfig.RouterConfig = createRouterConfig(profile.RouteMode)
	proxyOutboundConfig := getProxyOutboundDetourConfig(profile)
	freedomOutboundDetourConfig := createFreedomOutboundDetourConfig(profile.UseIPv6)
	if profile.RouteMode == 4 {
		jsonConfig.OutboundConfigs = []conf.OutboundDetourConfig{
			freedomOutboundDetourConfig,
			proxyOutboundConfig,
		}
	} else {
		jsonConfig.OutboundConfigs = []conf.OutboundDetourConfig{
			proxyOutboundConfig,
			freedomOutboundDetourConfig,
		}
	}
	// policy
	jsonConfig.Policy = creatPolicyConfig()
	// stats
	jsonConfig.Stats = &conf.StatsConfig{}
	return jsonConfig, nil
}
