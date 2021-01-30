module github.com/xxf098/go-tun2socks-build

go 1.15

require (
	github.com/eycorsican/go-tun2socks v1.16.11
	github.com/kr/text v0.2.0 // indirect
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/xtls/xray-core v1.2.3
	golang.org/x/mobile v0.0.0-20200801112145-973feb4309de
	golang.org/x/net v0.0.0-20210119194325-5f4716e94777
	gopkg.in/check.v1 v1.0.0-20200227125254-8fa46927fb4f // indirect
	v2ray.com/core v4.19.1+incompatible
)

// replace with v2ray-core path
replace v2ray.com/core v4.19.1+incompatible => ./v2ray-core