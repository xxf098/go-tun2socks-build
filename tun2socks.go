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

type vmess struct {
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

// type DBService interface {
// 	InsertProxyLog(target, tag string, startTime, endTime int64, uploadBytes, downloadBytes int32, recordType, dnsQueryType int32, dnsRequest, dnsResponse string, dnsNumIPs int32)
// }

func generateVmessConfig(profile vmess) ([]byte, error) {
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
		v2ray.Inbounds{
			Tag:      "http-in",
			Protocol: "http",
			Port:     8090,
			Listen:   "::",
		},
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
func StartV2Ray(packetFlow PacketFlow, vpnService VpnService, configBytes []byte, assetPath string, proxyLogDBPath string) error {
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
			log.Fatal("start V instance failed: %v", err)
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
		return nil
	}
	return errors.New("packetFlow is null")
}

func GenerateVmessString(
	host string,
	path string,
	tls string,
	add string,
	port int,
	aid int,
	net string,
	id string,
	loglevel string,
) (string, error) {
	profile := vmess{
		Host:     host,
		Path:     path,
		TLS:      tls,
		Add:      add,
		Port:     port,
		Aid:      aid,
		Net:      net,
		ID:       id,
		Loglevel: loglevel,
	}
	configBytes, err := generateVmessConfig(profile)
	if err != nil {
		log.Fatal("start V instance failed: %v", err)
		return "", err
	}
	return string(configBytes), nil
}

// StartV2Ray sets up lwIP stack, starts a V2Ray instance and registers the instance as the
// connection handler for tun2socks.
func StartV2RayWithVmess(
	packetFlow PacketFlow,
	vpnService VpnService,
	host string,
	path string,
	tls string,
	add string,
	port int,
	aid int,
	net string,
	id string,
	loglevel string,
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
		// v, err = vcore.StartInstance("json", configBytes)
		profile := vmess{
			Host:     host,
			Path:     path,
			TLS:      tls,
			Add:      add,
			Port:     port,
			Aid:      aid,
			Net:      net,
			ID:       id,
			Loglevel: loglevel,
		}
		configBytes, err := generateVmessConfig(profile)
		if err != nil {
			log.Fatal("start V instance failed: %v", err)
			return err
		}
		v, err = vcore.StartInstance("json", configBytes)
		if err != nil {
			log.Fatal("start V instance failed: %v", err)
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
