package features

import (
	"context"
	"encoding/json"
	"fmt"
	"net"

	vnet "github.com/xtls/xray-core/common/net"
	vcore "github.com/xtls/xray-core/core"
)

type VmessOptions struct {
	UseIPv6         bool   `json:"useIPv6"`
	Loglevel        string `json:"logLevel"`
	RouteMode       int    `json:"routeMode"`       // for SSRRAY
	DisableDNSCache bool   `json:"disableDNSCache"` // for SSRRAY
	EnableSniffing  bool   `json:"enableSniffing"`
	DNS             string `json:"dns"` // DNS Config
	AllowInsecure   bool   `json:"allowInsecure"`
	Mux             int    `json:"mux"`
	LocalPort       int    `json:"localPort"`
	ServerName      string `json:"serverName"`
}

func NewVmessOptions(opt []byte) VmessOptions {
	var options VmessOptions
	err := json.Unmarshal(opt, &options)
	if err != nil {
		options = VmessOptions{
			UseIPv6:        false,
			Loglevel:       "error",
			RouteMode:      0,
			EnableSniffing: true,
			DNS:            "8.8.8.8:53,223.5.5.5:53",
			AllowInsecure:  true,
			Mux:            -1,
		}
	}
	if options.Mux < 1 {
		options.Mux = -1
	}
	return options
}

type Vmess struct {
	Host       string
	Path       string
	TLS        string
	Add        string
	Port       int
	Aid        int
	Net        string
	ID         string
	Type       string // headerType
	Security   string // vnext.Security
	Encryption string // VlessUser.encryption
	Flow       string // VlessUser.flow
	SNI        string // tls sni
	Protocol   string
	VmessOptions
	Trojan      *Trojan
	Shadowsocks *Shadowsocks
}

func NewVmess(Host string, Path string, TLS string, Add string, Port int, Aid int, Net string, ID string, Type string, Security string, opt []byte) *Vmess {
	var options VmessOptions = NewVmessOptions(opt)
	return &Vmess{
		Host:         Host,
		Path:         Path,
		TLS:          TLS,
		Add:          Add,
		Port:         Port,
		Aid:          Aid,
		Net:          Net,
		ID:           ID,
		Type:         Type,
		Security:     Security,
		Protocol:     "vmess",
		VmessOptions: options,
		Trojan:       nil,
	}
}

type VmessDialer struct {
	Instance *vcore.Instance
}

func (d *VmessDialer) DialContext(ctx context.Context, network string, addr string) (net.Conn, error) {
	dest, err := vnet.ParseDestination(fmt.Sprintf("%s:%s", network, addr))
	if err != nil {
		return nil, err
	}
	return vcore.Dial(ctx, d.Instance, dest)
}
