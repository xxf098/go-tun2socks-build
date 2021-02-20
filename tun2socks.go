package tun2socks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"

	mobasset "golang.org/x/mobile/asset"
	vcore "v2ray.com/core"
	vproxyman "v2ray.com/core/app/proxyman"
	vbytespool "v2ray.com/core/common/bytespool"
	verrors "v2ray.com/core/common/errors"
	vnet "v2ray.com/core/common/net"
	v2filesystem "v2ray.com/core/common/platform/filesystem"
	v2stats "v2ray.com/core/features/stats"
	"v2ray.com/core/infra/conf"
	v2serial "v2ray.com/core/infra/conf/serial"
	vinternet "v2ray.com/core/transport/internet"

	xbytespool "github.com/xtls/xray-core/common/bytespool"
	xsession "github.com/xtls/xray-core/common/session"
	xcore "github.com/xtls/xray-core/core"
	x2stats "github.com/xtls/xray-core/features/stats"
	xserial "github.com/xtls/xray-core/infra/conf/serial"
	xinternet "github.com/xtls/xray-core/transport/internet"

	"github.com/eycorsican/go-tun2socks/core"
	"github.com/xxf098/go-tun2socks-build/features"
	"github.com/xxf098/go-tun2socks-build/ping"
	"github.com/xxf098/go-tun2socks-build/pool"
	"github.com/xxf098/go-tun2socks-build/runner"
	"github.com/xxf098/go-tun2socks-build/v2ray"
	"github.com/xxf098/go-tun2socks-build/xray"

)

var localDNS = "223.5.5.5:53"
var err error
var lwipStack core.LWIPStack
var x *xcore.Instance
var v *vcore.Instance
var mtuUsed int
var lwipTUNDataPipeTask *runner.Task
var updateStatusPipeTask *runner.Task
var tunDev *pool.Interface
var lwipWriter io.Writer
var statsManager v2stats.Manager
var xStatsManager x2stats.Manager
var isStopped = false

const (
	v2Asset = "v2ray.location.asset"
)

type errPathObjHolder struct{}

const (
	VMESS       string = "vmess"
	VLESS       string = "vless"
	TROJAN      string = "trojan"
	SHADOWSOCKS string = "shadowsocks"
)

func newError(values ...interface{}) *verrors.Error {
	return verrors.New(values...).WithPathObj(errPathObjHolder{})
}

type VmessOptions features.VmessOptions
type Trojan features.Trojan
type Vmess features.Vmess

func NewTrojan(Add string, Port int, Password string, SNI string, SkipCertVerify bool, opt []byte) *Trojan {
	t := Trojan(*features.NewTrojan(Add, Port, Password, SNI, SkipCertVerify, opt))
	return &t
}

func (t *Trojan) toVmess() *Vmess {
	trojan := features.Trojan(*t)
	return &Vmess{
		Protocol:     TROJAN,
		Trojan:       &trojan,
		VmessOptions: t.VmessOptions,
	}
}

func NewShadowSocks(Add string, Port int, ID string, Security string, opt []byte) *Vmess {
	options := features.NewVmessOptions(opt)
	return &Vmess{
		Add:          Add,
		Port:         Port,
		ID:           ID,
		Security:     Security,
		Protocol:     SHADOWSOCKS,
		VmessOptions: options,
		Trojan:       nil,
	}
}

// TODO: default value
func NewVmess(Host string, Path string, TLS string, Add string, Port int, Aid int, Net string, ID string, Type string, Security string, opt []byte) *Vmess {
	v := Vmess(*features.NewVmess(Host, Path, TLS, Add, Port, Aid, Net, ID, Type, Security, opt))
	return &v
}

func (profile *Vmess) getProxyOutboundDetourConfig() conf.OutboundDetourConfig {
	proxyOutboundConfig := conf.OutboundDetourConfig{}
	if profile.Protocol == VMESS {
		proxyOutboundConfig = createVmessOutboundDetourConfig(profile)
	}
	if profile.Protocol == TROJAN {
		proxyOutboundConfig = createTrojanOutboundDetourConfig(profile)
	}
	return proxyOutboundConfig
}

// TODO: try with native struct config conf.vmess
func generateVmessConfig(profile *Vmess) ([]byte, error) {
	vmessConfig := v2ray.VmessConfig{
		Stats:    v2ray.Stats{},
		Log:      v2ray.Log{Loglevel: "warning"},
		Inbounds: nil,
	}
	vmessConfig.DNS = v2ray.DNS{
		Servers: []string{"1.1.1.1"},
		Hosts:   v2ray.Hosts{"domain:googleapis.cn": "googleapis.com"},
	}
	vmessConfig.Routing = v2ray.Routing{
		DomainStrategy: "IPIfNonMatch",
		Rules: []v2ray.Rules{
			v2ray.Rules{
				Type:        "field",
				OutboundTag: "direct",
				IP:          []string{"geoip:private", "geoip:cn"},
			},
			v2ray.Rules{
				Type:        "field",
				OutboundTag: "direct",
				Domain:      []string{"geosite:cn"},
			},
		},
	}
	outbound := v2ray.Outbounds{
		Tag:      "proxy",
		Protocol: "vmess",
		Mux:      &v2ray.Mux{Enabled: false, Concurrency: -1},
		Settings: v2ray.OutboundsSettings{
			Vnext: []v2ray.Vnext{
				v2ray.Vnext{
					Address: profile.Add,
					Port:    profile.Port,
					Users: []v2ray.Users{
						v2ray.Users{
							AlterID:  profile.Aid,
							Email:    "v2ray@email.com",
							ID:       profile.ID,
							Security: profile.Security,
							Level:    8,
						},
					},
				},
			},
		},
		StreamSettings: &v2ray.StreamSettings{Network: "tcp", Security: ""},
	}
	if profile.Net == "ws" {
		outbound.StreamSettings = &v2ray.StreamSettings{
			Network: profile.Net,
			Wssettings: &v2ray.Wssettings{
				ConnectionReuse: true, Path: profile.Path,
			},
		}
		if profile.Host != "" {
			outbound.StreamSettings.Wssettings.Headers = v2ray.Headers{
				Host: profile.Host,
			}
		}
	}
	if profile.TLS == "tls" {
		outbound.StreamSettings.Security = profile.TLS
		outbound.StreamSettings.TLSSettings = &v2ray.TLSSettings{AllowInsecure: true}
	}
	// vmess must be the first
	vmessConfig.Outbounds = []v2ray.Outbounds{
		outbound,
		v2ray.Outbounds{
			Protocol: "freedom",
			Tag:      "direct",
			Settings: v2ray.OutboundsSettings{
				DomainStrategy: "UseIP",
			},
		},
	}
	vmessConfig.Policy = v2ray.Policy{
		Levels: map[string]v2ray.Level{
			"8": v2ray.Level{
				ConnIdle:     300,
				DownlinkOnly: 1,
				Handshake:    4,
				UplinkOnly:   1,
			},
		},
		System: v2ray.System{
			StatsOutboundUplink:   true,
			StatsOutboundDownlink: true,
		},
	}
	// errStr, _ := json.Marshal(vmessConfig)
	return json.MarshalIndent(vmessConfig, "", "    ")
}

func loadVmessConfig(profile *Vmess) (*conf.Config, error) {
	jsonConfig := &conf.Config{}
	jsonConfig.LogConfig = &conf.LogConfig{
		// AccessLog: "",
		// ErrorLog:  "",
		LogLevel: profile.Loglevel,
	}
	// https://github.com/Loyalsoldier/v2ray-rules-dat
	jsonConfig.DNSConfig = createDNSConfig(profile.RouteMode, profile.DNS)
	// update rules
	jsonConfig.RouterConfig = createRouterConfig(profile.RouteMode)
	// policy
	// connectionIdle := uint32(300)
	// downlinkOnly := uint32(1)
	// handshake := uint32(4)
	// uplinkOnly := uint32(1)
	// jsonConfig.Policy = &conf.PolicyConfig{
	// 	Levels: map[uint32]*conf.Policy{
	// 		8: &conf.Policy{
	// 			ConnectionIdle: &connectionIdle,
	// 			DownlinkOnly:   &downlinkOnly,
	// 			Handshake:      &handshake,
	// 			UplinkOnly:     &uplinkOnly,
	// 		},
	// 	},
	// 	System: &conf.SystemPolicy{
	// 		StatsInboundDownlink: true,
	// 		StatsInboundUplink:   true,
	// 	},
	// }
	// inboundsSettings, _ := json.Marshal(v2ray.InboundsSettings{
	// 	Auth: "noauth",
	// 	IP:   "127.0.0.1",
	// 	UDP:  true,
	// })
	// inboundsSettingsMsg := json.RawMessage(inboundsSettings)
	// jsonConfig.InboundConfigs = []conf.InboundDetourConfig{
	// 	conf.InboundDetourConfig{
	// 		Tag:       "socks-in",
	// 		Protocol:  "socks",
	// 		PortRange: &conf.PortRange{From: 8088, To: 8088},
	// 		ListenOn:  &conf.Address{vnet.IPAddress([]byte{127, 0, 0, 1})},
	// 		Settings:  &inboundsSettingsMsg,
	// 	},
	// 	conf.InboundDetourConfig{
	// 		Tag:       "http-in",
	// 		Protocol:  "http",
	// 		PortRange: &conf.PortRange{From: 8090, To: 8090},
	// 		ListenOn:  &conf.Address{vnet.IPAddress([]byte{127, 0, 0, 1})},
	// 	},
	// }
	proxyOutboundConfig := profile.getProxyOutboundDetourConfig()
	// if profile.Protocol == VMESS {
	// 	proxyOutboundConfig = createVmessOutboundDetourConfig(profile)
	// }
	// if profile.Protocol == TROJAN {
	// 	proxyOutboundConfig = createTrojanOutboundDetourConfig(profile)
	// }
	freedomOutboundDetourConfig := createFreedomOutboundDetourConfig(profile.UseIPv6)
	// order matters
	// GFWList mode, use 'direct' as default
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

// func logConfig(logLevel string) *vlog.Config {
// 	config := &vlog.Config{
// 		ErrorLogLevel: clog.Severity_Warning,
// 		ErrorLogType:  vlog.LogType_Console,
// 		AccessLogType: vlog.LogType_Console,
// 	}
// 	level := strings.ToLower(logLevel)
// 	switch level {
// 	case "debug":
// 		config.ErrorLogLevel = clog.Severity_Debug
// 	case "info":
// 		config.ErrorLogLevel = clog.Severity_Info
// 	case "error":
// 		config.ErrorLogLevel = clog.Severity_Error
// 	case "none":
// 		config.ErrorLogType = vlog.LogType_None
// 		config.AccessLogType = vlog.LogType_None
// 	}
// 	return config
// }

// func vmessToCoreConfig(profile *Vmess, inboundDetourConfig *conf.InboundDetourConfig) (*vcore.Config, error) {
// 	// vmess outbound
// 	vmessUser, _ := json.Marshal(conf.VMessAccount{
// 		ID:       profile.ID,
// 		AlterIds: uint16(profile.Aid),
// 		Security: "auto",
// 	})
// 	vmessOutboundConfig := conf.VMessOutboundConfig{
// 		Receivers: []*conf.VMessOutboundTarget{
// 			&conf.VMessOutboundTarget{
// 				Address: &conf.Address{Address: vnet.NewIPOrDomain(vnet.ParseAddress(profile.Add)).AsAddress()},
// 				Port:    uint16(profile.Port),
// 				Users:   []json.RawMessage{json.RawMessage(vmessUser)},
// 			},
// 		},
// 	}
// 	oc, err := vmessOutboundConfig.Build()
// 	if err != nil {
// 		return nil, err
// 	}
// 	outboundProxy := vcomserial.ToTypedMessage(oc)

// 	// freedom proxy
// 	freedomOutboundsSettings, _ := json.Marshal(v2ray.OutboundsSettings{DomainStrategy: "UseIP"})
// 	freedomOutboundsSettingsMsg := json.RawMessage(freedomOutboundsSettings)
// 	freedomProxy := conf.OutboundDetourConfig{
// 		Protocol: "freedom",
// 		Tag:      "direct",
// 		Settings: &freedomOutboundsSettingsMsg,
// 	}
// 	freedomConf, err := freedomProxy.Build()
// 	if err != nil {
// 		return nil, err
// 	}

// 	var transportSettings proto.Message
// 	var connectionReuse bool
// 	mode := profile.Net
// 	switch profile.Net {
// 	case "ws":
// 		transportSettings = &websocket.Config{
// 			Path: profile.Path,
// 			Header: []*websocket.Header{
// 				{Key: "Host", Value: profile.Host},
// 			},
// 		}
// 		connectionReuse = true
// 		mode = "websocket"
// 	case "quic":
// 		transportSettings = &quic.Config{
// 			Security: &protocol.SecurityConfig{Type: protocol.SecurityType_NONE},
// 		}
// 		profile.TLS = "tls"
// 	case "":
// 	default:
// 		return nil, newError("unsupported mode:", profile.Net)
// 	}

// 	streamConfig := vinternet.StreamConfig{
// 		ProtocolName: mode,
// 		TransportSettings: []*vinternet.TransportConfig{{
// 			ProtocolName: mode,
// 			Settings:     vcomserial.ToTypedMessage(transportSettings),
// 		}},
// 	}
// 	// TODO: support cert
// 	if profile.TLS == "tls" {
// 		tlsConfig := tls.Config{ServerName: profile.Host}
// 		streamConfig.SecurityType = vcomserial.GetMessageType(&tlsConfig)
// 		streamConfig.SecuritySettings = []*vcomserial.TypedMessage{vcomserial.ToTypedMessage(&tlsConfig)}
// 	}
// 	//router config
// 	routerConfig, err := createRouterConfig().Build()
// 	if err != nil {
// 		return nil, err
// 	}
// 	// dns config
// 	dnsConfig, err := createDNSConfig().Build()
// 	if err != nil {
// 		return nil, err
// 	}
// 	apps := []*vcomserial.TypedMessage{
// 		vcomserial.ToTypedMessage(&dispatcher.Config{}),
// 		vcomserial.ToTypedMessage(&vproxyman.InboundConfig{}),
// 		vcomserial.ToTypedMessage(&vproxyman.OutboundConfig{}),
// 		vcomserial.ToTypedMessage(logConfig(profile.Loglevel)),
// 		vcomserial.ToTypedMessage(routerConfig),
// 		vcomserial.ToTypedMessage(dnsConfig),
// 	}
// 	senderConfig := vproxyman.SenderConfig{StreamSettings: &streamConfig}
// 	if connectionReuse {
// 		senderConfig.MultiplexSettings = &vproxyman.MultiplexingConfig{Enabled: true, Concurrency: 16}
// 	}
// 	vcoreconfig := vcore.Config{
// 		Outbound: []*vcore.OutboundHandlerConfig{
// 			{
// 				SenderSettings: vcomserial.ToTypedMessage(&senderConfig),
// 				ProxySettings:  outboundProxy,
// 				Tag:            "proxy",
// 			},
// 			freedomConf,
// 		},
// 		App: apps,
// 	}
// 	if inboundDetourConfig != nil {
// 		inboundConfig, err := inboundDetourConfig.Build()
// 		if err != nil {
// 			return nil, err
// 		}
// 		vcoreconfig.Inbound = []*vcore.InboundHandlerConfig{
// 			inboundConfig,
// 		}
// 	}
// 	return &vcoreconfig, nil
// }

func loadVmessTestConfig(profile *Vmess, port uint32) (*conf.Config, error) {
	jsonConfig := &conf.Config{}
	jsonConfig.LogConfig = &conf.LogConfig{
		LogLevel: profile.Loglevel,
	}
	jsonConfig.DNSConfig = &conf.DNSConfig{
		Servers: []*conf.NameServerConfig{
			&conf.NameServerConfig{
				Address: &conf.Address{vnet.IPAddress([]byte{223, 5, 5, 5})},
				Port:    53,
			},
		},
	}
	if port > 0 && port < 65535 {
		jsonConfig.InboundConfigs = []conf.InboundDetourConfig{
			createInboundDetourConfig(port),
		}
	}
	jsonConfig.OutboundConfigs = []conf.OutboundDetourConfig{
		profile.getProxyOutboundDetourConfig(),
	}
	jsonConfig.Stats = &conf.StatsConfig{}
	return jsonConfig, nil
}

func startInstance(profile *Vmess, config *conf.Config) (*vcore.Instance, error) {
	if config == nil {
		defaultConfig, err := loadVmessConfig(profile)
		if err != nil {
			return nil, err
		}
		config = defaultConfig
	}
	coreConfig, err := config.Build()
	if err != nil {
		return nil, err
	}
	instance, err := vcore.New(coreConfig)
	if err != nil {
		return nil, err
	}
	if err := instance.Start(); err != nil {
		return nil, err
	}
	statsManager = instance.GetFeature(v2stats.ManagerType()).(v2stats.Manager)
	return instance, nil
}

func startXRayInstance(profile *Vmess) (*xcore.Instance, error) {
	config, err := loadVmessConfig(profile)
	if err != nil {
		return nil, err
	}
	config.DNSConfig = nil
	b, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	jsonConfig, err := xserial.DecodeJSONConfig(bytes.NewReader(b))
	jsonConfig.DNSConfig = xray.CreateDNSConfig(profile.VmessOptions)
	pbConfig, err := jsonConfig.Build()
	if err != nil {
		return nil, err
	}
	instance, err := xcore.New(pbConfig)
	if err != nil {
		return nil, err
	}
	err = instance.Start()
	if err != nil {
		return nil, err
	}
	xStatsManager = instance.GetFeature(x2stats.ManagerType()).(x2stats.Manager)
	return instance, nil
}

// VpnService should be implemented in Java/Kotlin.
type VpnService interface {
	// Protect is just a proxy to the VpnService.protect() method.
	// See also: https://developer.android.com/reference/android/net/VpnService.html#protect(int)
	Protect(fd int) bool
}

// PacketFlow should be implemented in Java/Kotlin.
type PacketFlow interface {
	// WritePacket should writes packets to the TUN fd.
	WritePacket(packet []byte)
}

// Write IP packets to the lwIP stack. Call this function in the main loop of
// the VpnService in Java/Kotlin, which should reads packets from the TUN fd.
func InputPacket(data []byte) {
	if lwipStack != nil {
		lwipStack.Write(data)
	}
}

type QuerySpeed interface {
	UpdateTraffic(up int64, down int64)
}

type TestLatency interface {
	UpdateLatency(id int, elapsed int64)
}

// SetNonblock puts the fd in blocking or non-blocking mode.
func SetNonblock(fd int, nonblocking bool) bool {
	err := syscall.SetNonblock(fd, nonblocking)
	if err != nil {
		return false
	}
	return true
}

// SetLocalDNS sets the DNS server that used by Go's default resolver, it accepts
// string in the form "host:port", e.g. 223.5.5.5:53
func SetLocalDNS(dns string) {
	localDNS = dns
}

// StartV2Ray sets up lwIP stack, starts a V2Ray instance and registers the instance as the
// connection handler for tun2socks.
func StartV2Ray(
	packetFlow PacketFlow,
	vpnService VpnService,
	logService LogService,
	querySpeed QuerySpeed,
	configBytes []byte,
	assetPath string) error {
	if packetFlow != nil {

		if lwipStack == nil {
			// Setup the lwIP stack.
			lwipStack = core.NewLWIPStack()
		}

		// Assets
		os.Setenv("v2ray.location.asset", assetPath)
		// log
		registerLogService(logService)

		// Protect file descriptors of net connections in the VPN process to prevent infinite loop.
		protectFd := func(s VpnService, fd int) error {
			if s.Protect(fd) {
				return nil
			} else {
				return errors.New(fmt.Sprintf("failed to protect fd %v", fd))
			}
		}
		netCtlr := func(network, address string, fd uintptr) error {
			return protectFd(vpnService, int(fd))
		}
		vinternet.RegisterDialerController(netCtlr)
		vinternet.RegisterListenerController(netCtlr)

		// Share the buffer pool.
		core.SetBufferPool(vbytespool.GetPool(core.BufSize))

		// Start the V2Ray instance.
		v, err = vcore.StartInstance("json", configBytes)
		if err != nil {
			log.Fatalf("start V instance failed: %v", err)
			return err
		}

		// Configure sniffing settings for traffic coming from tun2socks.
		sniffingConfig := &vproxyman.SniffingConfig{
			Enabled:             true,
			DestinationOverride: strings.Split("tls,http", ","),
		}
		ctx := contextWithSniffingConfig(context.Background(), sniffingConfig)

		// Register tun2socks connection handlers.
		// vhandler := v2ray.NewHandler(ctx, v)
		// core.RegisterTCPConnectionHandler(vhandler)
		// core.RegisterUDPConnectionHandler(vhandler)
		core.RegisterTCPConnHandler(v2ray.NewTCPHandler(ctx, v))
		core.RegisterUDPConnHandler(v2ray.NewUDPHandler(ctx, v, 3*time.Minute))

		// Write IP packets back to TUN.
		core.RegisterOutputFn(func(data []byte) (int, error) {
			if !isStopped {
				packetFlow.WritePacket(data)
			}
			return len(data), nil
		})

		statsManager = v.GetFeature(v2stats.ManagerType()).(v2stats.Manager)
		runner.CheckAndStop(updateStatusPipeTask)
		updateStatusPipeTask = createUpdateStatusPipeTask(querySpeed)
		isStopped = false
		logService.WriteLog(fmt.Sprintf("V2Ray %s started!", CheckVersion()))
		return nil
	}
	return errors.New("packetFlow is null")
}

func StartXRay(
	packetFlow PacketFlow,
	vpnService VpnService,
	logService LogService,
	querySpeed QuerySpeed,
	configBytes []byte,
	assetPath string) error {
	if packetFlow != nil {

		if lwipStack == nil {
			// Setup the lwIP stack.
			lwipStack = core.NewLWIPStack()
		}

		// Assets
		os.Setenv("xray.location.asset", assetPath)
		// log
		registerLogService(logService)

		// Protect file descriptors of net connections in the VPN process to prevent infinite loop.
		protectFd := func(s VpnService, fd int) error {
			if s.Protect(fd) {
				return nil
			} else {
				return errors.New(fmt.Sprintf("failed to protect fd %v", fd))
			}
		}
		netCtlr := func(network, address string, fd uintptr) error {
			return protectFd(vpnService, int(fd))
		}
		xinternet.RegisterDialerController(netCtlr)
		xinternet.RegisterListenerController(netCtlr)

		// Share the buffer pool.
		core.SetBufferPool(xbytespool.GetPool(core.BufSize))

		// Start the V2Ray instance.
		x, err = xray.StartInstance(configBytes)
		if err != nil {
			log.Fatalf("start V instance failed: %v", err)
			return err
		}

		// Configure sniffing settings for traffic coming from tun2socks.
		ctx := context.Background()
		content := xsession.ContentFromContext(ctx)
		if content == nil {
			content = new(xsession.Content)
			ctx = xsession.ContextWithContent(ctx, content)
		}

		core.RegisterTCPConnHandler(xray.NewTCPHandler(ctx, x))
		core.RegisterUDPConnHandler(xray.NewUDPHandler(ctx, x, 3*time.Minute))

		// Write IP packets back to TUN.
		core.RegisterOutputFn(func(data []byte) (int, error) {
			if !isStopped {
				packetFlow.WritePacket(data)
			}
			return len(data), nil
		})

		xStatsManager = x.GetFeature(x2stats.ManagerType()).(x2stats.Manager)
		runner.CheckAndStop(updateStatusPipeTask)
		updateStatusPipeTask = createUpdateStatusPipeTask(querySpeed)
		isStopped = false
		logService.WriteLog(fmt.Sprintf("XRay %s started!", CheckXVersion()))
		return nil
	}
	return errors.New("packetFlow is null")
}

func GenerateVmessString(profile *Vmess) (string, error) {
	configBytes, err := generateVmessConfig(profile)
	if err != nil {
		log.Fatalf("start V instance failed: %v", err)
		return "", err
	}
	return string(configBytes), nil
}

// StartV2Ray sets up lwIP stack, starts a V2Ray instance and registers the instance as the
// connection handler for tun2socks.
func StartV2RayWithVmess(
	packetFlow PacketFlow,
	vpnService VpnService,
	logService LogService,
	profile *Vmess,
	assetPath string) error {
	if packetFlow != nil {

		if lwipStack == nil {
			// Setup the lwIP stack.
			lwipStack = core.NewLWIPStack()
		}

		// Assets
		os.Setenv("v2ray.location.asset", assetPath)
		// logger
		registerLogService(logService)
		// Protect file descriptors of net connections in the VPN process to prevent infinite loop.
		protectFd := func(s VpnService, fd int) error {
			if s.Protect(fd) {
				return nil
			} else {
				return errors.New(fmt.Sprintf("failed to protect fd %v", fd))
			}
		}
		netCtlr := func(network, address string, fd uintptr) error {
			return protectFd(vpnService, int(fd))
		}
		vinternet.RegisterDialerController(netCtlr)
		vinternet.RegisterListenerController(netCtlr)

		// Share the buffer pool.
		core.SetBufferPool(vbytespool.GetPool(core.BufSize))

		// Start the V2Ray instance.
		// configBytes, err := generateVmessConfig(profile)
		// if err != nil {
		// 	return err
		// }
		// v, err = vcore.StartInstance("json", configBytes)
		v, err = startInstance(profile, nil)
		if err != nil {
			log.Fatalf("start V instance failed: %v", err)
			return err
		}
		ctx := context.WithValue(context.Background(), "routeMode", profile.RouteMode)
		// Configure sniffing settings for traffic coming from tun2socks.
		if profile.EnableSniffing || profile.RouteMode == 4 {
			sniffingConfig := &vproxyman.SniffingConfig{
				Enabled:             true,
				DestinationOverride: strings.Split("tls,http", ","),
			}
			ctx = contextWithSniffingConfig(ctx, sniffingConfig)
		}
		// Register tun2socks connection handlers.
		core.RegisterTCPConnHandler(v2ray.NewTCPHandler(ctx, v))
		core.RegisterUDPConnHandler(v2ray.NewUDPHandler(ctx, v, 3*time.Minute))

		// Write IP packets back to TUN.
		core.RegisterOutputFn(func(data []byte) (int, error) {
			if !isStopped {
				packetFlow.WritePacket(data)
			}
			return len(data), nil
		})

		isStopped = false
		logService.WriteLog("V2Ray Started!")
		return nil
	}
	return errors.New("packetFlow is null")
}

func StartV2RayWithTunFd(
	tunFd int,
	vpnService VpnService,
	logService LogService,
	querySpeed QuerySpeed,
	profile *Vmess,
	assetPath string) error {
	tunDev, err = pool.OpenTunDevice(tunFd)
	if err != nil {
		log.Fatalf("failed to open tun device: %v", err)
	}
	if lwipStack != nil {
		lwipStack.Close()
	}
	lwipStack = core.NewLWIPStack()
	lwipWriter = lwipStack.(io.Writer)

	// init v2ray
	os.Setenv("v2ray.location.asset", assetPath)
	registerLogService(logService)
	// Protect file descriptors of net connections in the VPN process to prevent infinite loop.
	protectFd := func(s VpnService, fd int) error {
		if s.Protect(fd) {
			return nil
		} else {
			return errors.New(fmt.Sprintf("failed to protect fd %v", fd))
		}
	}
	netCtlr := func(network, address string, fd uintptr) error {
		return protectFd(vpnService, int(fd))
	}
	vinternet.RegisterDialerController(netCtlr)
	vinternet.RegisterListenerController(netCtlr)
	core.SetBufferPool(vbytespool.GetPool(core.BufSize))

	v, err = startInstance(profile, nil)
	if err != nil {
		log.Fatalf("start V instance failed: %v", err)
		return err
	}
	ctx := context.WithValue(context.Background(), "routeMode", profile.RouteMode)
	// Configure sniffing settings for traffic coming from tun2socks.
	if profile.EnableSniffing || profile.RouteMode == 4 {
		sniffingConfig := &vproxyman.SniffingConfig{
			Enabled:             true,
			DestinationOverride: strings.Split("tls,http", ","),
		}
		ctx = contextWithSniffingConfig(ctx, sniffingConfig)
	}
	// Register tun2socks connection handlers.
	core.RegisterTCPConnHandler(v2ray.NewTCPHandler(ctx, v))
	core.RegisterUDPConnHandler(v2ray.NewUDPHandler(ctx, v, 3*time.Minute))

	// Write IP packets back to TUN.
	// output := make(chan []byte, 2400)
	core.RegisterOutputFn(func(data []byte) (int, error) {
		// buf := vbytespool.Alloc(int32(len(data)))
		// l := copy(buf, data)
		// output <- data
		return tunDev.Write(data)
	})
	// go func(ctx context.Context) {
	// 	for {
	// 		select {
	// 		case <-ctx.Done():
	// 			return
	// 		case buf := <-output:
	// 			tunDev.Write(buf)
	// 			// vbytespool.Free(buf)
	// 		}
	// 	}
	// }(ctx)
	// core.RegisterOutputCh(tunDev.WriteCh)
	isStopped = false
	runner.CheckAndStop(lwipTUNDataPipeTask)
	runner.CheckAndStop(updateStatusPipeTask)

	lwipTUNDataPipeTask = runner.Go(func(shouldStop runner.S) error {
		zeroErr := errors.New("nil")
		// handlePacket(ctx, tunDev, lwipWriter, shouldStop)
		tunDev.Copy(lwipWriter)
		return zeroErr // any errors?
	})
	updateStatusPipeTask = createUpdateStatusPipeTask(querySpeed)
	logService.WriteLog("V2Ray Started!")
	return nil
}

func StartXRayWithTunFd(
	tunFd int,
	vpnService VpnService,
	logService LogService,
	querySpeed QuerySpeed,
	profile *Vmess,
	assetPath string) error {
	tunDev, err = pool.OpenTunDevice(tunFd)
	if err != nil {
		log.Fatalf("failed to open tun device: %v", err)
	}
	if lwipStack != nil {
		lwipStack.Close()
	}
	lwipStack = core.NewLWIPStack()
	lwipWriter = lwipStack.(io.Writer)

	// init v2ray
	os.Setenv("v2ray.location.asset", assetPath)
	registerLogService(logService)
	// Protect file descriptors of net connections in the VPN process to prevent infinite loop.
	protectFd := func(s VpnService, fd int) error {
		if s.Protect(fd) {
			return nil
		} else {
			return errors.New(fmt.Sprintf("failed to protect fd %v", fd))
		}
	}
	netCtlr := func(network, address string, fd uintptr) error {
		return protectFd(vpnService, int(fd))
	}
	xinternet.RegisterDialerController(netCtlr)
	xinternet.RegisterListenerController(netCtlr)
	core.SetBufferPool(xbytespool.GetPool(core.BufSize))

	x, err = startXRayInstance(profile)
	if err != nil {
		log.Fatalf("start V instance failed: %v", err)
		return err
	}
	ctx := context.Background()
	content := xsession.ContentFromContext(ctx)
	if content == nil {
		content = new(xsession.Content)
		ctx = xsession.ContextWithContent(ctx, content)
	}
	// Register tun2socks connection handlers.
	core.RegisterTCPConnHandler(xray.NewTCPHandler(ctx, x))
	core.RegisterUDPConnHandler(xray.NewUDPHandler(ctx, x, 3*time.Minute))

	// Write IP packets back to TUN.
	core.RegisterOutputFn(func(data []byte) (int, error) {
		return tunDev.Write(data)
	})
	isStopped = false
	runner.CheckAndStop(lwipTUNDataPipeTask)
	runner.CheckAndStop(updateStatusPipeTask)

	lwipTUNDataPipeTask = runner.Go(func(shouldStop runner.S) error {
		zeroErr := errors.New("nil")
		tunDev.Copy(lwipWriter)
		return zeroErr // any errors?
	})
	updateStatusPipeTask = createUpdateStatusPipeTask(querySpeed)
	logService.WriteLog(fmt.Sprintf("Start XRay %s", CheckXVersion()))
	return nil
}

func handlePacket(ctx context.Context, tunDev *pool.Interface, lwipWriter io.Writer, shouldStop runner.S) {
	// inbound := make(chan []byte, 100)
	// outbound := make(chan []byte, 1000)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// defer close(outbound)

	// writer
	go func(ctx context.Context) {
		for {
			select {
			case buffer, ok := <-tunDev.ReadCh:
				if !ok {
					return
				}
				_, _ = lwipWriter.Write(buffer)
				vbytespool.Free(buffer)
			case <-ctx.Done():
				return
			}
		}
	}(ctx)
	tunDev.Run(ctx)
}

func createUpdateStatusPipeTask(querySpeed QuerySpeed) *runner.Task {
	return runner.Go(func(shouldStop runner.S) error {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		zeroErr := errors.New("nil")
		for {
			if shouldStop() {
				break
			}
			select {
			case <-ticker.C:
				up := QueryOutboundStats("proxy", "uplink")
				down := QueryOutboundStats("proxy", "downlink")
				querySpeed.UpdateTraffic(up, down)
				// case <-lwipTUNDataPipeTask.StopChan():
				// 	return errors.New("stopped")
			}
		}
		return zeroErr
	})
}

func StartTrojan(
	packetFlow PacketFlow,
	vpnService VpnService,
	logService LogService,
	trojan *Trojan,
	assetPath string) error {
	profile := trojan.toVmess()
	return StartV2RayWithVmess(packetFlow, vpnService, logService, profile, assetPath)
}

func StartTrojanTunFd(
	tunFd int,
	vpnService VpnService,
	logService LogService,
	querySpeed QuerySpeed,
	trojan *Trojan,
	assetPath string) error {
	profile := trojan.toVmess()
	return StartV2RayWithTunFd(tunFd, vpnService, logService, querySpeed, profile, assetPath)
}

// StopV2Ray stop v2ray
func StopV2Ray() {
	isStopped = true
	if tunDev != nil {
		tunDev.Stop()
	}
	runner.CheckAndStop(updateStatusPipeTask)
	runner.CheckAndStop(lwipTUNDataPipeTask)

	if lwipStack != nil {
		lwipStack.Close()
		lwipStack = nil
	}
	if statsManager != nil {
		statsManager.Close()
		statsManager = nil
	}
	if xStatsManager != nil {
		xStatsManager.Close()
		xStatsManager = nil
	}
	if v != nil {
		v.Close()
		v = nil
	}
	if x != nil {
		x.Close()
		x = nil
	}
}

// ~/go/src/v2ray.com/core/proxy/vmess/outbound/outbound.go
func QueryStats(direct string) int64 {
	if statsManager == nil {
		return 0
	}
	name := "vmess>>>" + "ssrray" + ">>>traffic>>>" + direct
	// name := "user>>>" + "xxf098@github.com" + ">>>traffic>>>" + direct + "link"
	counter := statsManager.GetCounter(name)
	if counter == nil {
		return 0
	}
	return counter.Set(0)
}

// add in v2ray-core v4.26.0
func QueryOutboundStats(tag string, direct string) int64 {
	if statsManager == nil {
		return 0
	}
	counter := statsManager.GetCounter(fmt.Sprintf("outbound>>>%s>>>traffic>>>%s", tag, direct))
	if counter == nil {
		return 0
	}
	return counter.Set(0)
}

// func queryStatsBg(log LogService) {
// 	for {
// 		if statsManager == nil {
// 			log.WriteLog("statsManager nil")
// 			return
// 		}
// 		name := "vmess>>>" + "ssrray" + ">>>traffic>>>" + "down"
// 		counter := statsManager.GetCounter(name)
// 		if counter == nil {
// 			log.WriteLog("counter nil")
// 		}
// 		time.Sleep(500 * time.Millisecond)
// 	}
// }

func init() {
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d, _ := vnet.ParseDestination(fmt.Sprintf("%v:%v", network, localDNS))
			return vinternet.DialSystem(ctx, d, nil)
		},
	}
}

func CheckVersion() string {
	return vcore.Version()
}

func CheckXVersion() string {
	return xcore.Version()
}

// TODO: update base on version
func CopyAssets(assetDir string, force bool) error {
	dats := [2]string{"geoip.dat", "geosite.dat"}
	for _, dat := range dats {
		_, err := os.Stat(assetDir + dat)
		if os.IsNotExist(err) || force {
			src, err := mobasset.Open("dat/" + dat)
			if err != nil {
				return err
			}
			dst, err := os.OpenFile(assetDir+dat, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
			if err != nil {
				return err
			}
			_, err = io.Copy(dst, src)
			if err != nil {
				return err
			}
			src.Close()
			dst.Close()
		}
	}
	return nil
}

func initV2Env(assetperfix string) {
	if os.Getenv(v2Asset) != "" {
		return
	}
	//Initialize asset API, Since Raymond Will not let notify the asset location inside Process,
	//We need to set location outside V2Ray
	os.Setenv(v2Asset, assetperfix)
	//Now we handle read
	v2filesystem.NewFileReader = func(path string) (io.ReadCloser, error) {
		if strings.HasPrefix(path, assetperfix) {
			p := path[len(assetperfix)+1:]
			//is it overridden?
			//by, ok := overridedAssets[p]
			//if ok {
			//	return os.Open(by)
			//}
			return mobasset.Open(p)
		}
		return os.Open(path)
	}
}

func TestConfig(ConfigureFileContent string, assetperfix string) error {
	initV2Env(assetperfix)
	// os.Setenv("v2ray.location.asset", assetperfix)
	_, err := v2serial.LoadJSONConfig(strings.NewReader(ConfigureFileContent))
	return err
}

func TestVmessLatency(profile *Vmess, port int) (int64, error) {
	// os.Setenv("v2ray.location.asset", assetPath)
	var proxyPort = testProxyPort
	if port > 0 && port < 65535 {
		proxyPort = uint32(port)
	} else {
		proxyPort = uint32(0)
	}
	config, err := loadVmessTestConfig(profile, proxyPort)
	if err != nil {
		return 0, err
	}
	server, err := startInstance(profile, config)
	if err != nil {
		return 0, err
	}
	defer server.Close()
	runtime.GC()
	// socksProxy := fmt.Sprintf("socks5://127.0.0.1:%d", proxyPort)
	// socksProxy, err := addInboundHandler(server)
	// return testLatency(socksProxy)
	if proxyPort == 0 {
		return testLatencyWithHTTP(server)
	} else {
		return testLatencyWithSocks5("127.0.0.1", proxyPort)
	}
}

func TestVmessDownload(profile *Vmess, timeout time.Duration, cb TestLatency) (int64, error) {
	c := make(chan int64)
	go func() {
		for {
			select {
			case s := <-c:
				if s < 0 {
					return
				}
				// fmt.Println(download.ByteCountIEC(s))
				cb.UpdateLatency(-1, s)
			}
		}
	}()
	return v2rayDownload(profile, 15*time.Second, c)
}

func BatchTestVmessCoreLatency(link string, concurrency int, testLatency TestLatency) {
	if concurrency < 1 {
		concurrency = 5
	}
	links := strings.Split(link, ",")
	resultCh := ping.BatchTestLinks(links, concurrency, []ping.RunFunc{})
	for range links {
		select {
		case r := <-resultCh:
			testLatency.UpdateLatency(r.Index, r.Result)
		}
	}
}

func TestTrojanLatency(trojan *Trojan) (int64, error) {
	profile := trojan.toVmess()
	return TestVmessLatency(profile, -1)
}

func TestURLLatency(url string) (int64, error) {
	return testLatency(url)
}

func TestTCPPing(host string, port int) (int64, error) {
	tcpping := ping.NewTCPPing(host, port)
	result := <-tcpping.Start()
	return result.Get()
}

func TestConfigLatency(configBytes []byte, assetPath string) (int64, error) {
	os.Setenv("v2ray.location.asset", assetPath)
	server, err := vcore.StartInstance("json", configBytes)
	if err != nil {
		return 0, err
	}
	defer server.Close()
	runtime.GC()
	socksProxy, err := addInboundHandler(server)
	if err != nil {
		return 0, err
	}
	return testLatency(socksProxy)
}

func ConvertJSONToVmess(configBytes []byte) (*Vmess, error) {
	vmess := &Vmess{
		Host:     "",
		Path:     "",
		TLS:      "",
		Add:      "",
		Port:     0,
		Aid:      0,
		Net:      "",
		ID:       "",
		Type:     "",
		Security: "",
	}
	config, err := DecodeJSONConfig(bytes.NewReader(configBytes))
	if err != nil {
		return nil, err
	}
	outboundConfig := config.OutboundConfigs[0]
	settings := []byte("{}")
	if outboundConfig.Settings != nil {
		settings = ([]byte)(*outboundConfig.Settings)
	}
	outboundConfigLoader := conf.NewJSONConfigLoader(conf.ConfigCreatorCache{
		"blackhole": func() interface{} { return new(conf.BlackholeConfig) },
		"freedom":   func() interface{} { return new(conf.FreedomConfig) },
		// "http":        func() interface{} { return new(conf.HttpClientConfig) },
		"shadowsocks": func() interface{} { return new(conf.ShadowsocksClientConfig) },
		"vmess":       func() interface{} { return new(conf.VMessOutboundConfig) },
		"vless":       func() interface{} { return new(conf.VLessOutboundConfig) },
		"socks":       func() interface{} { return new(conf.SocksClientConfig) },
		"mtproto":     func() interface{} { return new(conf.MTProtoClientConfig) },
		"dns":         func() interface{} { return new(conf.DNSOutboundConfig) },
	}, "protocol", "settings")
	if outboundConfig.Protocol != "vmess" && outboundConfig.Protocol != "vless" {
		return vmess, err
	}
	rawConfig, err := outboundConfigLoader.LoadWithID(settings, outboundConfig.Protocol)
	if err != nil {
		return nil, err
	}
	if outboundConfig.StreamSetting != nil {
		vmess.Net = string(*outboundConfig.StreamSetting.Network)
	}
	if outboundConfig.Protocol == "vmess" {
		vmess.Protocol = VMESS
		vmessOutboundConfig, ok := rawConfig.(*conf.VMessOutboundConfig)
		if !ok {
			return nil, newError("Not A VMess Config")
		}
		for _, vnext := range vmessOutboundConfig.Receivers {
			vmess.Add = vnext.Address.String()
			vmess.Port = int(vnext.Port)
			account := new(conf.VMessAccount)
			for _, rawUser := range vnext.Users {
				if err := json.Unmarshal(rawUser, account); err == nil {
					vmess.ID = account.ID
					vmess.Aid = int(account.AlterIds)
					vmess.Security = account.Security
				}
			}
		}
	}
	if outboundConfig.Protocol == "vless" {
		vlessOutboundConfig, ok := rawConfig.(*conf.VLessOutboundConfig)
		if !ok {
			return nil, newError("Not A VLess Config")
		}
		vmess.Protocol = VLESS
		for _, vnext := range vlessOutboundConfig.Vnext {
			vmess.Add = vnext.Address.String()
			vmess.Port = int(vnext.Port)
			account := new(conf.VMessAccount)
			for _, rawUser := range vnext.Users {
				if err := json.Unmarshal(rawUser, account); err == nil {
					vmess.ID = account.ID
					vmess.Aid = int(account.AlterIds)
					vmess.Security = account.Security
				}
			}
		}
	}
	return vmess, nil
}

func GetFreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
