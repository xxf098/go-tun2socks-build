module github.com/xxf098/go-tun2socks-build

go 1.19

require (
	github.com/eycorsican/go-tun2socks v1.16.11
	github.com/kr/text v0.2.0 // indirect
	// github.com/v2fly/v2ray-core/v4 v4.43.0
	github.com/xtls/xray-core v1.7.5
	github.com/xxf098/lite-proxy v0.0.0
	golang.org/x/mobile v0.0.0-20221110043201-43a038452099
	golang.org/x/net v0.7.0
)

require (
	github.com/Dreamacro/go-shadowsocks2 v0.1.8 // indirect
	github.com/andybalholm/brotli v1.0.4 // indirect
	github.com/dgryski/go-metro v0.0.0-20211217172704-adc40b04c140 // indirect
	github.com/francoispqt/gojay v1.2.13 // indirect
	github.com/ghodss/yaml v1.0.1-0.20220118164431-d8423dcdf344 // indirect
	github.com/go-task/slim-sprig v0.0.0-20210107165309-348f09dbbbc0 // indirect
	github.com/gofrs/uuid v4.3.1+incompatible // indirect
	github.com/golang/freetype v0.0.0-20170609003504-e2365dfdc4a0 // indirect
	github.com/golang/mock v1.6.0 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/google/pprof v0.0.0-20230207041349-798e818bf904 // indirect
	github.com/gorilla/websocket v1.5.0 // indirect
	github.com/klauspost/compress v1.15.15 // indirect
	github.com/klauspost/cpuid/v2 v2.2.3 // indirect
	github.com/miekg/dns v1.1.50 // indirect
	github.com/onsi/ginkgo/v2 v2.8.1 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pires/go-proxyproto v0.6.2 // indirect
	github.com/quic-go/qtls-go1-18 v0.2.0 // indirect
	github.com/quic-go/qtls-go1-19 v0.2.0 // indirect
	github.com/quic-go/qtls-go1-20 v0.1.0 // indirect
	github.com/quic-go/quic-go v0.32.0 // indirect
	github.com/refraction-networking/utls v1.2.2 // indirect
	github.com/riobard/go-bloom v0.0.0-20200614022211-cdc8013cb5b3 // indirect
	github.com/sagernet/sing v0.1.6 // indirect
	github.com/sagernet/sing-shadowsocks v0.1.1-0.20230202035033-e3123545f2f7 // indirect
	github.com/sagernet/wireguard-go v0.0.0-20221116151939-c99467f53f2c // indirect
	github.com/seiflotfy/cuckoofilter v0.0.0-20220411075957-e3b120b3f5fb // indirect
	github.com/v2fly/ss-bloomring v0.0.0-20210312155135-28617310f63e // indirect
	github.com/xtls/go v0.0.0-20230107031059-4610f88d00f3 // indirect
	github.com/xtls/reality v0.0.0-20230217102704-085bdf2104d3 // indirect
	go.starlark.net v0.0.0-20230128213706-3f75dec8e403 // indirect
	go.uber.org/atomic v1.10.0 // indirect
	golang.org/x/crypto v0.6.0 // indirect
	golang.org/x/exp v0.0.0-20230213192124-5e25df0256eb // indirect
	golang.org/x/image v0.2.0 // indirect
	golang.org/x/mod v0.8.0 // indirect
	golang.org/x/sync v0.1.0 // indirect
	golang.org/x/sys v0.5.0 // indirect
	golang.org/x/text v0.7.0 // indirect
	golang.org/x/time v0.3.0 // indirect
	golang.org/x/tools v0.6.0 // indirect
	google.golang.org/genproto v0.0.0-20230209215440-0dfe4f8abfcc // indirect
	google.golang.org/grpc v1.53.0 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	gvisor.dev/gvisor v0.0.0-20220901235040-6ca97ef2ce1c // indirect
	lukechampine.com/blake3 v1.1.7 // indirect
)

// replace with v2ray-core path
replace (
	// github.com/v2fly/v2ray-core/v4 v4.43.0 => ../v2ray-core
	github.com/xtls/xray-core v1.7.5 => ../xray-core
	// git clone https://github.com/xxf098/LiteSpeedTest.git lite-proxy
	github.com/xxf098/lite-proxy v0.0.0 => ../lite-proxy
)
