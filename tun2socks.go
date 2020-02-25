package tun2socks

import (
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
	vfilesystem "v2ray.com/core/common/platform/filesystem"
	vconf "v2ray.com/core/infra/conf"
	vserial "v2ray.com/core/infra/conf/serial"
	vinternet "v2ray.com/core/transport/internet"

	"github.com/eycorsican/go-tun2socks/core"
	"github.com/xxf098/go-tun2socks-build/v2ray"
)

var err error
var lwipStack core.LWIPStack
var v *vcore.Instance

var isStopped = false
var localDNS = "223.5.5.5:53"

const (
	v2Asset = "v2ray.location.asset"
)

type errPathObjHolder struct{}

func newError(values ...interface{}) *verrors.Error {
	return verrors.New(values...).WithPathObj(errPathObjHolder{})
}

// constructor export New
type Vmess struct {
	Host     string
	Path     string
	TLS      string
	Add      string
	Port     int
	Aid      int
	Net      string
	ID       string
	Type     string // headerType
	Loglevel string
}

// TODO: default value
func NewVmess(Host string, Path string, TLS string, Add string, Port int, Aid int, Net string, ID string, Type string, Loglevel string) *Vmess {
	return &Vmess{
		Host:     Host,
		Path:     Path,
		TLS:      TLS,
		Add:      Add,
		Port:     Port,
		Aid:      Aid,
		Net:      Net,
		ID:       ID,
		Type:     Type,
		Loglevel: Loglevel,
	}
}

// type DBService interface {
// 	InsertProxyLog(target, tag string, startTime, endTime int64, uploadBytes, downloadBytes int32, recordType, dnsQueryType int32, dnsRequest, dnsResponse string, dnsNumIPs int32)
// }

// TODO: try with native struct config vconf.vmess
func generateVmessConfig(profile *Vmess) ([]byte, error) {
	vmessConfig := v2ray.VmessConfig{}
	vmessConfig.Log = v2ray.Log{Access: "", Error: "", Loglevel: profile.Loglevel}
	vmessConfig.DNS = v2ray.DNS{
		Servers: []string{"1.0.0.1", "localhost"},
		Hosts:   v2ray.Hosts{"baidu.com": "127.0.0.1", "umeng.com": "127.0.0.1"},
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
	vmessConfig.Inbounds = []v2ray.Inbounds{
		v2ray.Inbounds{
			Tag:      "socks-in",
			Protocol: "socks",
			Port:     8088,
			Listen:   "::",
			InboundsSettings: &v2ray.InboundsSettings{
				Auth: "noauth",
				IP:   "127.0.0.1",
				UDP:  true,
			},
		},
		// v2ray.Inbounds{
		// 	Tag:      "http-in",
		// 	Protocol: "http",
		// 	Port:     8090,
		// 	Listen:   "::",
		// },
	}
	outbound := v2ray.Outbounds{
		Tag:      "proxy",
		Protocol: "vmess",
		Mux:      &v2ray.Mux{Enabled: true},
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
							Security: "auto",
						},
					},
				},
			},
		},
		StreamSettings: &v2ray.StreamSettings{},
	}
	if profile.Net == "ws" {
		outbound.StreamSettings = &v2ray.StreamSettings{
			Network: profile.Net,
			Wssettings: v2ray.Wssettings{
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
	// errStr, _ := json.Marshal(vmessConfig)
	return json.MarshalIndent(vmessConfig, "", "    ")
}

func loadVmessConfig(profile *Vmess) (*vconf.Config, error) {
	jsonConfig := &vconf.Config{}
	jsonConfig.LogConfig = &vconf.LogConfig{
		// AccessLog: "",
		// ErrorLog:  "",
		LogLevel: profile.Loglevel,
	}
	// https://github.com/Loyalsoldier/v2ray-rules-dat
	jsonConfig.DNSConfig = createDNSConfig()
	// update rules
	jsonConfig.RouterConfig = createRouterConfig()
	// inboundsSettings, _ := json.Marshal(v2ray.InboundsSettings{
	// 	Auth: "noauth",
	// 	IP:   "127.0.0.1",
	// 	UDP:  true,
	// })
	// inboundsSettingsMsg := json.RawMessage(inboundsSettings)
	// jsonConfig.InboundConfigs = []vconf.InboundDetourConfig{
	// 	vconf.InboundDetourConfig{
	// 		Tag:       "socks-in",
	// 		Protocol:  "socks",
	// 		PortRange: &vconf.PortRange{From: 8088, To: 8088},
	// 		ListenOn:  &vconf.Address{vnet.IPAddress([]byte{127, 0, 0, 1})},
	// 		Settings:  &inboundsSettingsMsg,
	// 	},
	// 	vconf.InboundDetourConfig{
	// 		Tag:       "http-in",
	// 		Protocol:  "http",
	// 		PortRange: &vconf.PortRange{From: 8090, To: 8090},
	// 		ListenOn:  &vconf.Address{vnet.IPAddress([]byte{127, 0, 0, 1})},
	// 	},
	// }
	vmessOutboundDetourConfig := createVmessOutboundDetourConfig(profile)
	freedomOutboundDetourConfig := createFreedomOutboundDetourConfig()
	// order matters
	jsonConfig.OutboundConfigs = []vconf.OutboundDetourConfig{
		vmessOutboundDetourConfig,
		freedomOutboundDetourConfig,
	}
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

// func vmessToCoreConfig(profile *Vmess, inboundDetourConfig *vconf.InboundDetourConfig) (*vcore.Config, error) {
// 	// vmess outbound
// 	vmessUser, _ := json.Marshal(vconf.VMessAccount{
// 		ID:       profile.ID,
// 		AlterIds: uint16(profile.Aid),
// 		Security: "auto",
// 	})
// 	vmessOutboundConfig := vconf.VMessOutboundConfig{
// 		Receivers: []*vconf.VMessOutboundTarget{
// 			&vconf.VMessOutboundTarget{
// 				Address: &vconf.Address{Address: vnet.NewIPOrDomain(vnet.ParseAddress(profile.Add)).AsAddress()},
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
// 	freedomProxy := vconf.OutboundDetourConfig{
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

func loadVmessTestConfig(profile *Vmess) (*vconf.Config, error) {
	jsonConfig := &vconf.Config{}
	jsonConfig.LogConfig = &vconf.LogConfig{
		LogLevel: profile.Loglevel,
	}
	jsonConfig.DNSConfig = &vconf.DnsConfig{
		Servers: []*vconf.NameServerConfig{
			&vconf.NameServerConfig{
				Address: &vconf.Address{vnet.IPAddress([]byte{223, 5, 5, 5})},
				Port:    53,
			},
		},
	}
	jsonConfig.InboundConfigs = []vconf.InboundDetourConfig{
		createInboundDetourConfig(testProxyPort),
	}
	jsonConfig.OutboundConfigs = []vconf.OutboundDetourConfig{
		createVmessOutboundDetourConfig(profile),
	}
	return jsonConfig, nil
}

func startInstance(profile *Vmess, config *vconf.Config) (*vcore.Instance, error) {
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
	configBytes []byte,
	assetPath string) error {
	if packetFlow == nil {
		return errors.New("packetFlow is null")
	}
	// if dbService != nil {
	// 	vsession.DefaultDBService = dbService
	// }

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
	ctx := vproxyman.ContextWithSniffingConfig(context.Background(), sniffingConfig)

	// Register tun2socks connection handlers.
	// vhandler := v2ray.NewHandler(ctx, v)
	// core.RegisterTCPConnectionHandler(vhandler)
	// core.RegisterUDPConnectionHandler(vhandler)
	core.RegisterTCPConnHandler(v2ray.NewTCPHandler(ctx, v))
	core.RegisterUDPConnHandler(v2ray.NewUDPHandler(ctx, v, 2*time.Minute))

	// Write IP packets back to TUN.
	core.RegisterOutputFn(func(data []byte) (int, error) {
		if !isStopped {
			packetFlow.WritePacket(data)
		}
		return len(data), nil
	})

	isStopped = false
	logService.WriteLog("V2Ray started!")
	return nil
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
	if packetFlow == nil {
		return errors.New("packetFlow is null")
	}

	// if dbService != nil {
	// 	vsession.DefaultDBService = dbService
	// }

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
	v, err = startInstance(profile, nil)
	if err != nil {
		log.Fatalf("start V instance failed: %v", err)
		return err
	}

	// Configure sniffing settings for traffic coming from tun2socks.
	sniffingConfig := &vproxyman.SniffingConfig{
		Enabled:             true,
		DestinationOverride: strings.Split("tls,http", ","),
	}
	ctx := vproxyman.ContextWithSniffingConfig(context.Background(), sniffingConfig)

	// Register tun2socks connection handlers.
	core.RegisterTCPConnHandler(v2ray.NewTCPHandler(ctx, v))
	core.RegisterUDPConnHandler(v2ray.NewUDPHandler(ctx, v, 2*time.Minute))

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

// StopV2Ray stop v2ray
func StopV2Ray() {
	isStopped = true
	if lwipStack != nil {
		lwipStack.Close()
		lwipStack = nil
	}
	v.Close()
	v = nil
	// vsession.DefaultDBService = nil
}

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
			defer src.Close()

			dst, err := os.OpenFile(assetDir+dat, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
			if err != nil {
				return err
			}
			defer dst.Close()

			_, err = io.Copy(dst, src)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func initV2Env(assetPrefix string) {
	if os.Getenv(v2Asset) != "" {
		return
	}
	//Initialize asset API, Since Raymond Will not let notify the asset location inside Process,
	//We need to set location outside V2Ray
	os.Setenv(v2Asset, assetPrefix)
	//Now we handle read
	vfilesystem.NewFileReader = func(path string) (io.ReadCloser, error) {
		if strings.HasPrefix(path, assetPrefix) {
			p := path[len(assetPrefix)+1:]
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

func TestConfig(configFileContent string, assetPrefix string) error {
	initV2Env(assetPrefix)
	// os.Setenv("v2ray.location.asset", assetPrefix)
	_, err := vserial.LoadJSONConfig(strings.NewReader(configFileContent))
	return err
}

func TestVmessLatency(profile *Vmess, assetPath string) (int64, error) {
	os.Setenv(v2Asset, assetPath)
	config, err := loadVmessTestConfig(profile)
	if err != nil {
		return 0, err
	}
	server, err := startInstance(profile, config)
	if err != nil {
		return 0, err
	}
	defer server.Close()
	runtime.GC()
	socksProxy := fmt.Sprintf("socks5://127.0.0.1:%d", testProxyPort)
	// socksProxy, err := addInboundHandler(server)
	return testLatency(socksProxy)
}

func TestConfigLatency(configBytes []byte, assetPath string) (int64, error) {
	os.Setenv(v2Asset, assetPath)
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
