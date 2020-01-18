package tun2socks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"

	mobasset "golang.org/x/mobile/asset"
	vcore "v2ray.com/core"
	vapplog "v2ray.com/core/app/log"
	vproxyman "v2ray.com/core/app/proxyman"
	vbytespool "v2ray.com/core/common/bytespool"
	verrors "v2ray.com/core/common/errors"
	vcommonlog "v2ray.com/core/common/log"
	vnet "v2ray.com/core/common/net"
	v2filesystem "v2ray.com/core/common/platform/filesystem"
	"v2ray.com/core/infra/conf"
	v2serial "v2ray.com/core/infra/conf/serial"
	vinternet "v2ray.com/core/transport/internet"

	"github.com/eycorsican/go-tun2socks/core"
	"github.com/xxf098/go-tun2socks-build/v2ray"
)

var localDNS = "223.5.5.5:53"
var err error
var lwipStack core.LWIPStack
var v *vcore.Instance
var isStopped = false

const (
	v2Assert = "v2ray.location.asset"
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
	Loglevel string
}

func NewVmess(Host string, Path string, TLS string, Add string, Port int, Aid int, Net string, ID string, Loglevel string) *Vmess {
	return &Vmess{
		Host:     Host,
		Path:     Path,
		TLS:      TLS,
		Add:      Add,
		Port:     Port,
		Aid:      Aid,
		Net:      Net,
		ID:       ID,
		Loglevel: Loglevel,
	}
}

// type DBService interface {
// 	InsertProxyLog(target, tag string, startTime, endTime int64, uploadBytes, downloadBytes int32, recordType, dnsQueryType int32, dnsRequest, dnsResponse string, dnsNumIPs int32)
// }

// TODO: try with native struct config conf.vmess
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

func loadVmessConfig(profile *Vmess) (*conf.Config, error) {
	jsonConfig := &conf.Config{}
	jsonConfig.LogConfig = &conf.LogConfig{
		// AccessLog: "",
		// ErrorLog:  "",
		LogLevel: profile.Loglevel,
	}
	// https://github.com/Loyalsoldier/v2ray-rules-dat
	jsonConfig.DNSConfig = &conf.DnsConfig{
		Servers: []*conf.NameServerConfig{
			&conf.NameServerConfig{
				Address: &conf.Address{vnet.IPAddress([]byte{223, 5, 5, 5})},
				Port:    53,
				// Domains: []string{"geosite:cn"},
			},
			// &conf.NameServerConfig{Address: &conf.Address{vnet.IPAddress([]byte{8, 8, 8, 8})}, Port: 53},
			// &conf.NameServerConfig{Address: &conf.Address{vnet.IPAddress([]byte{1, 1, 1, 1})}, Port: 53},
			// &conf.NameServerConfig{Address: &conf.Address{vnet.IPAddress([]byte{9, 9, 9, 9})}, Port: 53},
			&conf.NameServerConfig{Address: &conf.Address{vnet.IPAddress([]byte{127, 0, 0, 1})}, Port: 53},
			// &conf.NameServerConfig{Address: &conf.Address{vnet.DomainAddress("localhost")}, Port: 53},
		},
		Hosts: v2ray.BlockHosts,
	}
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
	// update rules
	jsonConfig.RouterConfig = &conf.RouterConfig{
		DomainStrategy: &domainStrategy,
		RuleList:       []json.RawMessage{json.RawMessage(rule1), json.RawMessage(rule2), json.RawMessage(rule3)},
	}
	inboundsSettings, _ := json.Marshal(v2ray.InboundsSettings{
		Auth: "noauth",
		IP:   "127.0.0.1",
		UDP:  true,
	})
	inboundsSettingsMsg := json.RawMessage(inboundsSettings)
	jsonConfig.InboundConfigs = []conf.InboundDetourConfig{
		conf.InboundDetourConfig{
			Tag:       "socks-in",
			Protocol:  "socks",
			PortRange: &conf.PortRange{From: 8088, To: 8088},
			ListenOn:  &conf.Address{vnet.IPAddress([]byte{127, 0, 0, 1})},
			Settings:  &inboundsSettingsMsg,
		},
		// conf.InboundDetourConfig{
		// 	Tag:       "http-in",
		// 	Protocol:  "http",
		// 	PortRange: &conf.PortRange{From: 8090, To: 8090},
		// 	ListenOn:  &conf.Address{vnet.IPAddress([]byte{127, 0, 0, 1})},
		// },
	}

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
	// second
	outboundsSettings2, _ := json.Marshal(v2ray.OutboundsSettings{DomainStrategy: "UseIP"})
	outboundsSettingsMsg2 := json.RawMessage(outboundsSettings2)
	// order matters
	jsonConfig.OutboundConfigs = []conf.OutboundDetourConfig{
		vmessOutboundDetourConfig,
		conf.OutboundDetourConfig{
			Protocol: "freedom",
			Tag:      "direct",
			Settings: &outboundsSettingsMsg2,
		},
	}
	return jsonConfig, nil
}

func startInstance(profile *Vmess) (*vcore.Instance, error) {
	config, err := loadVmessConfig(profile)
	if err != nil {
		return nil, err
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

func registerLog(logService LogService) {
	if logService != nil {
		vapplog.RegisterHandlerCreator(vapplog.LogType_Console, func(lt vapplog.LogType,
			options vapplog.HandlerCreatorOptions) (vcommonlog.Handler, error) {
			return vcommonlog.NewLogger(createLogWriter(logService)), nil
		})
	}
}

// StartV2Ray sets up lwIP stack, starts a V2Ray instance and registers the instance as the
// connection handler for tun2socks.
func StartV2Ray(
	packetFlow PacketFlow,
	vpnService VpnService,
	logService LogService,
	configBytes []byte,
	assetPath string) error {
	if packetFlow != nil {
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
		registerLog(logService)

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
		registerLog(logService)
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
		v, err = startInstance(profile)
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
	return errors.New("packetFlow is null")
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
	if os.Getenv(v2Assert) != "" {
		return
	}
	//Initialize asset API, Since Raymond Will not let notify the asset location inside Process,
	//We need to set location outside V2Ray
	os.Setenv(v2Assert, assetperfix)
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
	// inboundManager := server.GetFeature(vinbound.ManagerType()).(vinbound.Manager)
	// if inboundManager == nil {
	// 	return 0, newError("No Proxy")
	// }
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

func TestVmessLatency(profile *Vmess, assetPath string) (int64, error) {
	os.Setenv("v2ray.location.asset", assetPath)
	server, err := startInstance(profile)
	if err != nil {
		return 0, err
	}
	defer server.Close()
	socksProxy := "socks5://127.0.0.1:8088"
	return testLatency(socksProxy)
}

func TestConfigLatency(configBytes []byte, assetPath string) (int64, error) {
	os.Setenv("v2ray.location.asset", assetPath)
	server, err := vcore.StartInstance("json", configBytes)
	if err != nil {
		return 0, err
	}
	defer server.Close()
	runtime.GC()
	// register inbound
	const proxyPort = 8899
	// inboundsSettings, _ := json.Marshal(v2ray.InboundsSettings{
	// 	Auth: "noauth",
	// 	IP:   "127.0.0.1",
	// 	UDP:  true,
	// })
	// inboundsSettingsMsg := json.RawMessage(inboundsSettings)
	// inboundDetourConfig := conf.InboundDetourConfig{
	// 	Tag:       "socks-in",
	// 	Protocol:  "socks",
	// 	PortRange: &conf.PortRange{From: proxyPort, To: proxyPort},
	// 	ListenOn:  &conf.Address{vnet.IPAddress([]byte{127, 0, 0, 1})},
	// 	Settings:  &inboundsSettingsMsg,
	// }
	// inboundConfig, err := inboundDetourConfig.Build()
	// if err != nil {
	// 	return 0, err
	// }
	inboundConfig, err := createInboundConfig(proxyPort)
	if err != nil {
		return 0, err
	}
	vcore.AddInboundHandler(server, inboundConfig)
	socksProxy := fmt.Sprintf("socks5://127.0.0.1:%d", proxyPort)
	return testLatency(socksProxy)
}
