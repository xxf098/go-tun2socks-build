module github.com/xxf098/go-tun2socks-build

go 1.15

require (
	github.com/eycorsican/go-tun2socks v1.16.8
	golang.org/x/mobile v0.0.0-20191210151939-1a1fef82734d // indirect
	v2ray.com/core v4.19.1+incompatible
)

// replace with v2ray-core path
replace v2ray.com/core v4.19.1+incompatible => ./v2ray-core