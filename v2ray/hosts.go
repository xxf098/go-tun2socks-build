package v2ray

import (
	vnet "v2ray.com/core/common/net"
	"v2ray.com/core/infra/conf"
)

var localhost = &conf.Address{vnet.IPAddress([]byte{0, 0, 0, 0})}
var BlockHosts = map[string]*conf.Address{
	"umeng.com":            localhost,
	"baidu.com":            localhost,
	"sogou.com":            localhost,
	"doubleclick.net":      localhost,
	"byteimg.com":          localhost,
	"ixigua.com":           localhost,
	"snssdk.com":           localhost,
	"uc.com":               localhost,
	"uc.cn":                localhost,
	"umengcloud.com":       localhost,
	"baidustatic.com":      localhost,
	"auspiciousvp.com":     localhost,
	"www.auspiciousvp.com": localhost,
	"cnzz.com":             localhost,
	"toutiaopage.com":      localhost,
	"douyin.com":           localhost,
	"bdstatic.com":         localhost,
	"360.cn":               localhost,
	"umtrack.com":          localhost,
	"umsns.com":            localhost,
	"qhupdate.com":         localhost,
	"qhimg.com":            localhost,
	"at3.doubanio.com":     localhost,
	"p.pinduoduo.com":      localhost,
}
