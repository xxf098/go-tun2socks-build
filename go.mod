module github.com/xxf098/go-tun2socks-build

go 1.16

require (
	github.com/eycorsican/go-tun2socks v1.16.11
	github.com/kr/text v0.2.0 // indirect
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/v2fly/v2ray-core/v4 v4.38.0
	github.com/xtls/xray-core v1.4.2
	github.com/xxf098/lite-proxy v0.0.0
	golang.org/x/mobile v0.0.0-20210220033013-bdb1ca9a1e08
	golang.org/x/net v0.0.0-20210415231046-e915ea6b2b7d
	google.golang.org/genproto v0.0.0-20210310155132-4ce2db91004e // indirect
	gopkg.in/check.v1 v1.0.0-20200227125254-8fa46927fb4f // indirect
)

// replace with v2ray-core path
replace (
	github.com/v2fly/v2ray-core/v4 v4.38.0 => ../v2ray-core
	github.com/xtls/xray-core v1.4.2 => ../xray-core
	github.com/xxf098/lite-proxy v0.0.0 => ../lite-proxy
)
