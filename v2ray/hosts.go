package v2ray

import (
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf"
)

var localhost = conf.NewHostAddress(&conf.Address{net.IPAddress([]byte{0, 0, 0, 0})}, nil)
var google = conf.NewHostAddress(&conf.Address{net.DomainAddress("googleapis.com")}, nil)

// no prefix is fullmatch
var BlockHosts = map[string]*conf.HostAddress{
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
	"at3.doubanio.com":     localhost,
	"p.pinduoduo.com":      localhost,
	"domain:googleapis.cn": google,
}

// no prefix is substr
var BlockDomains = []string{
	"175.25.22.142",
	"175.25.22.149",
	"175.25.22.141",
	"auspiciousvp.com",
	// "www.auspiciousvp.com",
	"cnzz.com",
	// "toutiao",
	// "snssdk.com",
	// "ixiguavideo.com",
	// "domian:sogou.com",
	"domian:doubleclick.net",
	"360totalsecurity.com",
	"ad.doubanio.com",
	"at3.doubanio.com",
	"p.pinduoduo.com",
}

var DirectDomains = []string{
	"brave.com",
}
