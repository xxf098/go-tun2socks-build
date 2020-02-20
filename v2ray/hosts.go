package v2ray

import (
	vnet "v2ray.com/core/common/net"
	"v2ray.com/core/infra/conf"
)

var localhost = &conf.Address{vnet.IPAddress([]byte{0, 0, 0, 0})}

// no prefix is fullmatch
var BlockHosts = map[string]*conf.Address{
	// "domain:umeng.com": localhost,
	// "domain:baidu.com":       localhost,
	// "domain:sogou.com":       localhost,
	"domain:doubleclick.net": localhost,
	// "domain:byteimg.com":     localhost,
	// "domain:ixigua.com":      localhost,
	// "domain:snssdk.com":      localhost,
	// "domain:uc.com":          localhost,
	// "domain:uc.cn":           localhost,
	// "domain:umengcloud.com": localhost,
	// "keyword:baidustatic":    localhost,
	"keyword:auspiciousvp": localhost,
	"domain:cnzz.com":      localhost,
	// "domain:toutiaopage.com": localhost,
	// "domain:douyin.com":      localhost,
	// "domain:bdstatic.com":    localhost,
	// "domain:360.cn":       localhost,
	// "domain:umtrack.com":  localhost,
	// "domain:umsns.com":    localhost,
	// "domain:qhupdate.com": localhost,
	// "domain:qhimg.com":    localhost,
	"at3.doubanio.com": localhost,
	"p.pinduoduo.com":  localhost,
}

// no prefix is substr
var BlockDomains = []string{
	// "baidu",
	// "bdstatic",
	"umeng",
	"auspiciousvp.com",
	"www.auspiciousvp.com",
	"cnzz.com",
	// "toutiao",
	// "snssdk.com",
	// "ixiguavideo.com",
	// "domian:sogou.com",
	"domian:doubleclick.net",
	// "byteimg.com",
	// "ixigua.com",
	// "domian:uc.com",
	// "domian:uc.cn",
	// "ucweb.com",
	// "domian:360.cn",
	// "qhupdate.com",
	// "360safe.com",
	"360totalsecurity.com",
	"at3.doubanio.com",
	"p.pinduoduo.com",
}
