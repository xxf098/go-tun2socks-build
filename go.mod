module github.com/xxf098/go-tun2socks-build

go 1.21

require (
	github.com/eycorsican/go-tun2socks v1.16.11
	github.com/kr/text v0.2.0 // indirect
	github.com/sagernet/sing v0.2.9
	// github.com/v2fly/v2ray-core/v4 v4.43.0
	github.com/xtls/xray-core v1.8.4
	github.com/xxf098/lite-proxy v0.0.0
	golang.org/x/mobile v0.0.0-20230818142238-7088062f872d
	golang.org/x/net v0.14.0
)

require (
	github.com/Dreamacro/go-shadowsocks2 v0.1.8 // indirect
	github.com/andybalholm/brotli v1.0.5 // indirect
	github.com/dgryski/go-metro v0.0.0-20211217172704-adc40b04c140 // indirect
	github.com/francoispqt/gojay v1.2.13 // indirect
	github.com/gaukas/godicttls v0.0.4 // indirect
	github.com/ghodss/yaml v1.0.1-0.20220118164431-d8423dcdf344 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/gofrs/uuid v4.3.1+incompatible // indirect
	github.com/golang/freetype v0.0.0-20170609003504-e2365dfdc4a0 // indirect
	github.com/golang/mock v1.6.0 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/google/pprof v0.0.0-20230821062121-407c9e7a662f // indirect
	github.com/gorilla/websocket v1.5.0 // indirect
	github.com/klauspost/compress v1.16.7 // indirect
	github.com/klauspost/cpuid/v2 v2.2.5 // indirect
	github.com/miekg/dns v1.1.55 // indirect
	github.com/onsi/ginkgo/v2 v2.12.0 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pires/go-proxyproto v0.7.0 // indirect
	github.com/quic-go/qtls-go1-20 v0.3.3 // indirect
	github.com/quic-go/quic-go v0.38.1 // indirect
	github.com/refraction-networking/utls v1.4.3 // indirect
	github.com/riobard/go-bloom v0.0.0-20200614022211-cdc8013cb5b3 // indirect
	github.com/sagernet/sing-shadowsocks v0.2.4 // indirect
	github.com/sagernet/wireguard-go v0.0.0-20221116151939-c99467f53f2c // indirect
	github.com/seiflotfy/cuckoofilter v0.0.0-20220411075957-e3b120b3f5fb // indirect
	github.com/v2fly/ss-bloomring v0.0.0-20210312155135-28617310f63e // indirect
	github.com/xtls/reality v0.0.0-20230828171259-e426190d57f6 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go4.org/netipx v0.0.0-20230824141953-6213f710f925 // indirect
	golang.org/x/crypto v0.12.0 // indirect
	golang.org/x/exp v0.0.0-20230725093048-515e97ebf090 // indirect
	golang.org/x/image v0.2.0 // indirect
	golang.org/x/mod v0.12.0 // indirect
	golang.org/x/sync v0.3.0 // indirect
	golang.org/x/sys v0.11.0 // indirect
	golang.org/x/text v0.12.0 // indirect
	golang.org/x/time v0.3.0 // indirect
	golang.org/x/tools v0.12.1-0.20230818130535-1517d1a3ba60 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230822172742-b8732ec3820d // indirect
	google.golang.org/grpc v1.57.0 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	gvisor.dev/gvisor v0.0.0-20230822212503-5bf4e5f98744 // indirect
	lukechampine.com/blake3 v1.2.1 // indirect
)

// replace with v2ray-core path
replace (
	// github.com/v2fly/v2ray-core/v4 v4.43.0 => ../v2ray-core
	github.com/xtls/xray-core v1.8.4 => ../xray-core
	// git clone https://github.com/xxf098/LiteSpeedTest.git lite-proxy
	github.com/xxf098/lite-proxy v0.0.0 => ../lite-proxy
)
