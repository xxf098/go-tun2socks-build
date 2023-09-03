package tun2socks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	vproxyman "github.com/xtls/xray-core/app/proxyman"
	verrors "github.com/xtls/xray-core/common/errors"
	vnet "github.com/xtls/xray-core/common/net"
	vsession "github.com/xtls/xray-core/common/session"
	vcore "github.com/xtls/xray-core/core"
	vinbound "github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/infra/conf"

	// "github.com/xtls/xray-core/infra/conf/cfgcommon"
	json_reader "github.com/xtls/xray-core/infra/conf/json"
	"github.com/xxf098/go-tun2socks-build/features"
	"github.com/xxf098/go-tun2socks-build/ping"
	"github.com/xxf098/go-tun2socks-build/pool"
	"github.com/xxf098/go-tun2socks-build/settings"
	"github.com/xxf098/go-tun2socks-build/v2ray"
	lconfig "github.com/xxf098/lite-proxy/config"
	loutbound "github.com/xxf098/lite-proxy/outbound"
	lutils "github.com/xxf098/lite-proxy/utils"
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
	defaultReadBufferSize = 4096
	remoteHost            = "clients3.google.com"
)

var (
	strHTTP11 = []byte("HTTP/1.1")
)

func testLatency(url string) (int64, error) {
	// socksProxyURL, err := url.Parse(proxy)
	// if err != nil {
	// 	return 0, err
	// }
	// socksTransport := &http.Transport{Proxy: http.ProxyURL(socksProxyURL)}
	// client := &http.Client{Transport: socksTransport, Timeout: time.Second * 3}
	client := &http.Client{Timeout: time.Second * 3}
	resp, err := client.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if err != nil {
		return 0, err
	}
	// fmt.Println(resp.Status)
	// fmt.Println(resp.StatusCode)
	// if resp.StatusCode == 204 {
	start := time.Now()
	resp1, err := client.Get(url)
	elapsed := time.Since(start)
	if err != nil {
		return 0, err
	}
	defer resp1.Body.Close()
	if resp1.StatusCode == 204 || resp1.StatusCode == 200 {
		return elapsed.Milliseconds(), nil
	}
	// }
	return 0, newError(resp.Status)
}

// https://github.com/golang/net/blob/master/internal/socks/client.go
// scoks5 test vmess test
// TODO: error message
func testLatencyWithSocks5(ip string, port uint32) (int64, error) {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	err = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if err != nil {
		return 0, err
	}
	// remoteHost := "clients3.google.com"
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
	if err = send204Request(&conn, 1200*time.Millisecond); err != nil {
		return 0, err
	}
	elapsed := time.Since(start)
	return elapsed.Milliseconds(), nil
}

// TODO: refactor
func send204Request(conn *net.Conn, timeout time.Duration) error {
	err = (*conn).SetDeadline(time.Now().Add(timeout))
	if err != nil {
		return err
	}
	// remoteHost := "clients3.google.com"
	httpRequest := fmt.Sprintf("GET /generate_204 HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36\r\n\r\n", remoteHost)
	if _, err = fmt.Fprintf(*conn, httpRequest); err != nil {
		return err
	}
	buf := make([]byte, 128)
	n, err := (*conn).Read(buf)
	if err != nil && err != io.EOF {
		return err
	}
	httpResponse := lutils.B2s(buf[:n])
	if !strings.HasPrefix(httpResponse, "HTTP/1.1 204 No Content") {
		return fmt.Errorf("error response: %s", httpResponse)
	}
	return nil
}

func sendCode204Request(conn *net.Conn, timeout time.Duration) error {
	err = (*conn).SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return err
	}
	// remoteHost := "clients3.google.com"
	// httpRequest := fmt.Sprintf("GET /generate_204 HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36\r\n\r\n", remoteHost)
	httpRequest := "GET /generate_204 HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36\r\n\r\n"
	if _, err = fmt.Fprintf(*conn, httpRequest, remoteHost); err != nil {
		return err
	}
	buf := make([]byte, 128)
	_, err := (*conn).Read(buf)
	if err != nil && err != io.EOF {
		return err
	}
	_, err = parseFirstLine(buf)
	return err
}

func parseFirstLine(buf []byte) (int, error) {
	bNext := buf
	var b []byte
	var err error
	for len(b) == 0 {
		if b, bNext, err = nextLine(bNext); err != nil {
			return 0, err
		}
	}

	// parse protocol
	n := bytes.IndexByte(b, ' ')
	if n < 0 {
		return 0, fmt.Errorf("cannot find whitespace in the first line of response %q", buf)
	}
	b = b[n+1:]

	// parse status code
	statusCode, n, err := parseUintBuf(b)
	if err != nil {
		return 0, fmt.Errorf("cannot parse response status code: %s. Response %q", err, buf)
	}
	if len(b) > n && b[n] != ' ' {
		return 0, fmt.Errorf("unexpected char at the end of status code. Response %q", buf)
	}

	if statusCode == 204 || statusCode == 200 {
		return len(buf) - len(bNext), nil
	}
	return 0, errors.New("wrong status code")
}

func nextLine(b []byte) ([]byte, []byte, error) {
	nNext := bytes.IndexByte(b, '\n')
	if nNext < 0 {
		return nil, nil, errors.New("need more data: cannot find trailing lf")
	}
	n := nNext
	if n > 0 && b[n-1] == '\r' {
		n--
	}
	return b[:n], b[nNext+1:], nil
}

func parseUintBuf(b []byte) (int, int, error) {
	n := len(b)
	if n == 0 {
		return -1, 0, errors.New("empty integer")
	}
	v := 0
	for i := 0; i < n; i++ {
		c := b[i]
		k := c - '0'
		if k > 9 {
			if i == 0 {
				return -1, i, errors.New("unexpected first char found. Expecting 0-9")
			}
			return v, i, nil
		}
		vNew := 10*v + int(k)
		// Test for overflow.
		if vNew < v {
			return -1, i, errors.New("too long int")
		}
		v = vNew
	}
	return v, n, nil
}

func v2rayDownload(profile *Vmess, timeout time.Duration, resultChan chan<- int64) (int64, error) {
	var max int64 = 0
	config, err := loadVmessTestConfig(profile, 0)
	if err != nil {
		return max, err
	}
	instance, err := startInstance(profile, config)
	if err != nil {
		return max, err
	}
	dialer := features.VmessDialer{
		Instance: instance,
	}
	httpTransport := &http.Transport{
		DialContext: dialer.DialContext,
	}
	httpClient := &http.Client{Transport: httpTransport, Timeout: timeout}
	req, err := http.NewRequest("GET", "https://download.microsoft.com/download/2/0/E/20E90413-712F-438C-988E-FDAA79A8AC3D/dotnetfx35.exe", nil)
	if err != nil {
		return max, err
	}
	response, err := httpClient.Do(req)
	if err != nil {
		return max, err
	}
	defer response.Body.Close()
	start := time.Now()
	prev := start
	var total int64
	for {
		buf := pool.NewBytes(20 * 1024)
		nr, er := response.Body.Read(buf)
		total += int64(nr)
		pool.FreeBytes(buf)
		now := time.Now()
		if now.Sub(prev) >= time.Second || err != nil {
			prev = now
			if resultChan != nil {
				resultChan <- total
			}
			if max < total {
				max = total
			}
			total = 0
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	resultChan <- -1
	return max, nil
}

func testLatencyWithHTTP(v *vcore.Instance) (int64, error) {
	dest := vnet.Destination{
		Address: vnet.DomainAddress("clients3.google.com"),
		Network: vnet.Network_TCP,
		Port:    vnet.Port(80),
	}
	sid := vsession.NewID()
	ctx := vsession.ContextWithID(context.Background(), sid)
	conn, err := vcore.Dial(ctx, v, dest)
	if err != nil {
		return 0, fmt.Errorf("dial V proxy connection failed: %v", err)
	}
	defer conn.Close()
	timeout := 1235 * time.Millisecond
	if err = sendCode204Request(&conn, timeout); err != nil {
		timeout = 2358 * time.Millisecond
	}
	// timeout then retry
	start := time.Now()
	if err = sendCode204Request(&conn, timeout); err != nil {
		return 0, err
	}
	elapsed := time.Since(start)
	return elapsed.Milliseconds(), nil
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
		Tag:      "socks-in",
		Protocol: "socks",
		PortList: &conf.PortList{Range: []conf.PortRange{conf.PortRange{From: proxyPort, To: proxyPort}}},
		ListenOn: &conf.Address{vnet.IPAddress([]byte{127, 0, 0, 1})},
		Settings: &inboundsSettingsMsg,
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
						Level:    8,
						Security: profile.Security,
					},
				},
			},
		},
	})
	outboundsSettingsMsg1 := json.RawMessage(outboundsSettings1)
	muxEnabled := false
	if profile.VmessOptions.Mux > 0 {
		muxEnabled = true
	} else {
		profile.VmessOptions.Mux = -1
	}
	tcp := conf.TransportProtocol("tcp")
	vmessOutboundDetourConfig := conf.OutboundDetourConfig{
		Protocol:    "vmess",
		Tag:         "proxy",
		MuxSettings: &conf.MuxConfig{Enabled: muxEnabled, Concurrency: int16(profile.VmessOptions.Mux)},
		Settings:    &outboundsSettingsMsg1,
		StreamSetting: &conf.StreamConfig{
			Network:  &tcp,
			Security: "",
		},
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
		vmessOutboundDetourConfig.StreamSetting.TLSSettings = tlsConfig
	}
	return vmessOutboundDetourConfig
}

// TODO: refactor
func configVmessTransport(profile *Vmess, outboundsSettingsMsg1 json.RawMessage) conf.OutboundDetourConfig {
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
					UserAgent:      []string{"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36"},
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

func createVlessOutboundDetourConfig(profile *Vmess) conf.OutboundDetourConfig {
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

func createTrojanOutboundDetourConfig(profile *Vmess) conf.OutboundDetourConfig {
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
			&settings.TrojanServerTarget{
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
	streamSetting := &conf.StreamConfig{
		Security: "tls",
		Network:  &transportProtocol,
		TLSSettings: &conf.TLSConfig{
			Insecure:   config.SkipCertVerify,
			ServerName: config.SNI,
		},
	}
	if config.Net == "ws" {
		transportProtocol := conf.TransportProtocol(config.Net)
		streamSetting = &conf.StreamConfig{
			Security: "tls",
			Network:  &transportProtocol,
			TLSSettings: &conf.TLSConfig{
				Insecure:   config.SkipCertVerify,
				ServerName: config.SNI,
			},
			WSSettings: &conf.WebSocketConfig{Path: config.Path},
		}
		if len(config.Host) < 1 {
			config.Host = config.SNI
		}
		streamSetting.WSSettings.Headers = map[string]string{"Host": config.Host}
	}
	trojanOutboundDetourConfig := conf.OutboundDetourConfig{
		Protocol:      "trojan",
		Tag:           "proxy",
		Settings:      &outboundsSettingsMsg,
		StreamSetting: streamSetting,
	}
	return trojanOutboundDetourConfig
}

func createShadowsocksOutboundDetourConfig(profile *Vmess) conf.OutboundDetourConfig {
	config := profile.Shadowsocks
	outboundsSettings, _ := json.Marshal(settings.ShadowsocksOutboundsSettings{
		Servers: []*settings.ShadowsocksServerTarget{
			&settings.ShadowsocksServerTarget{
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
		Domain:      []string{"domain:googleapis.cn", "domain:gstatic.com", "domain:ampproject.org"},
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

func creatPolicyConfig() *conf.PolicyConfig {
	handshake := uint32(4)
	connIdle := uint32(300)
	downlinkOnly := uint32(1)
	uplinkOnly := uint32(1)
	return &conf.PolicyConfig{
		Levels: map[uint32]*conf.Policy{
			8: &conf.Policy{
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

// remove https://github.com/v2ray/v2ray-core/blob/02b658cd2beb5968818c7ed37388fb348b9b9cb9/app/dns/server.go#L362
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
		Hosts:   &conf.HostsWrapper{Hosts: v2ray.BlockHosts},
		Servers: nameServerConfig,
	}
}

func toNameServerConfig(hostport string) *conf.NameServerConfig {
	// doh
	if strings.HasPrefix("https", hostport) {
		newConfig := &conf.NameServerConfig{Address: &conf.Address{vnet.ParseAddress(hostport)}}
		return newConfig
	}
	if hostport == "8.8.8.8:53" {
		newConfig := &conf.NameServerConfig{Address: &conf.Address{vnet.ParseAddress("https://dns.google/dns-query")}}
		return newConfig
	}
	if hostport == "1.1.1.1:53" {
		newConfig := &conf.NameServerConfig{Address: &conf.Address{vnet.ParseAddress("https://1.1.1.1/dns-query")}}
		return newConfig
	}

	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return nil
	}
	newConfig := &conf.NameServerConfig{Address: &conf.Address{vnet.ParseAddress(host)}, Port: uint16(p)}
	return newConfig
}

type offset struct {
	line int
	char int
}

func findOffset(b []byte, o int) *offset {
	if o >= len(b) || o < 0 {
		return nil
	}

	line := 1
	char := 0
	for i, x := range b {
		if i == o {
			break
		}
		if x == '\n' {
			line++
			char = 0
		} else {
			char++
		}
	}

	return &offset{line: line, char: char}
}

func DecodeJSONConfig(reader io.Reader) (*conf.Config, error) {
	jsonConfig := &conf.Config{}

	jsonContent := bytes.NewBuffer(make([]byte, 0, 10240))
	jsonReader := io.TeeReader(&json_reader.Reader{
		Reader: reader,
	}, jsonContent)
	decoder := json.NewDecoder(jsonReader)

	if err := decoder.Decode(jsonConfig); err != nil {
		var pos *offset
		cause := verrors.Cause(err)
		switch tErr := cause.(type) {
		case *json.SyntaxError:
			pos = findOffset(jsonContent.Bytes(), int(tErr.Offset))
		case *json.UnmarshalTypeError:
			pos = findOffset(jsonContent.Bytes(), int(tErr.Offset))
		}
		if pos != nil {
			return nil, newError("failed to read config file at line ", pos.line, " char ", pos.char).Base(err)
		}
		return nil, newError("failed to read config file").Base(err)
	}

	return jsonConfig, nil
}

// ContextWithSniffingConfig is a wrapper of session.ContextWithContent.
// Deprecated. Use session.ContextWithContent directly.
func contextWithSniffingConfig(ctx context.Context, c *vproxyman.SniffingConfig) context.Context {
	content := vsession.ContentFromContext(ctx)
	if content == nil {
		content = new(vsession.Content)
		ctx = vsession.ContextWithContent(ctx, content)
	}
	content.SniffingRequest.Enabled = c.Enabled
	content.SniffingRequest.OverrideDestinationForProtocol = c.DestinationOverride
	return ctx
}

func runCore(index int, link string, c chan<- ping.TestResult) (bool, error) {
	option, err := lconfig.VmessLinkToVmessConfigIP(link, false)
	if err != nil {
		return false, err
	}
	profile := NewVmess(option.Host,
		option.Path,
		option.TLS,
		option.Add,
		option.PortInt,
		option.AidInt,
		option.Net,
		option.ID,
		v2ray.VMESS,
		option.Security,
		[]byte{})
	elapse, err := TestVmessLatency(profile, -1)
	result := ping.TestResult{
		Result:   elapse,
		Index:    index,
		Err:      err,
		Protocol: "vmess",
	}
	c <- result
	return false, err
}

func vmess2Lite(profile *Vmess) (loutbound.Dialer, error) {
	option, err := profile2Option(profile)
	if err != nil {
		return nil, err
	}
	vmessOption, ok := option.(*loutbound.VmessOption)
	if !ok {
		return nil, newError("not support protocol")
	}
	return loutbound.NewVmess(vmessOption)
}

func trojan2Lite(profile *Vmess) (loutbound.Dialer, error) {
	return nil, newError("not support protocol")
}

func ss2Lite(profile *Vmess) (loutbound.Dialer, error) {
	option, _ := profile2Option(profile)
	ssOption, ok := option.(*loutbound.ShadowSocksOption)
	if !ok {
		return nil, newError("not support protocol")
	}
	return loutbound.NewShadowSocks(ssOption)
}

func profile2Option(profile *Vmess) (interface{}, error) {
	if profile.Protocol == v2ray.VMESS {
		aidRaw, _ := json.Marshal(profile.Aid)
		portRaw, _ := json.Marshal(profile.Port)
		c := &lconfig.VmessConfig{
			Add:        profile.Add,
			Aid:        aidRaw,
			Host:       profile.Host,
			ID:         profile.ID,
			Net:        profile.Net,
			Path:       profile.Path,
			Port:       portRaw,
			TLS:        profile.TLS,
			Type:       profile.Type,
			Security:   profile.Security,
			ServerName: profile.VmessOptions.ServerName,
		}
		return lconfig.VmessConfigToVmessOption(c)
	}
	if profile.Protocol == v2ray.SHADOWSOCKS {
		opt := &loutbound.ShadowSocksOption{
			Server:   profile.Add,
			Port:     profile.Port,
			Password: profile.ID,
			Cipher:   profile.Security,
		}
		return opt, nil
	}
	return nil, newError("not support protocol")
}

type latencyResult struct {
	elapsed int64
	err     error
}
