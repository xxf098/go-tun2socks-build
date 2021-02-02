package xray

import (
	"bytes"
	"net"
	"strconv"
	"strings"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xxf098/go-tun2socks-build/features"
)

// Start start with config
func StartInstance(config []byte) (*core.Instance, error) {
	jsonConfig, err := serial.DecodeJSONConfig(bytes.NewReader(config))
	if err != nil {
		return nil, err
	}
	pbConfig, err := jsonConfig.Build()
	if err != nil {
		return nil, err
	}
	instance, err := core.New(pbConfig)
	if err != nil {
		return nil, err
	}
	err = instance.Start()
	if err != nil {
		return nil, err
	}
	return instance, nil
}

func CreateDNSConfig(option features.VmessOptions) *conf.DNSConfig {
	routeMode := option.RouteMode
	dnsConf := option.DNS
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
		Servers: nameServerConfig,
	}
}

func toNameServerConfig(hostport string) *conf.NameServerConfig {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return nil
	}
	newConfig := &conf.NameServerConfig{Address: &conf.Address{xnet.ParseAddress(host)}, Port: uint16(p)}
	return newConfig
}
