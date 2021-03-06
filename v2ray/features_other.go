// +build !ios,!android

package v2ray

import (
	_ "github.com/v2fly/v2ray-core/v4/app/commander"
	_ "github.com/v2fly/v2ray-core/v4/app/log/command"
	_ "github.com/v2fly/v2ray-core/v4/app/proxyman/command"
	_ "github.com/v2fly/v2ray-core/v4/app/stats/command"

	_ "github.com/v2fly/v2ray-core/v4/app/reverse"

	_ "github.com/v2fly/v2ray-core/v4/transport/internet/domainsocket"
)
