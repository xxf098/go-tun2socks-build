package xray

import (
	"context"
	"fmt"
	"io"
	"net"

	xnet "github.com/xtls/xray-core/common/net"
	xsession "github.com/xtls/xray-core/common/session"
	xcore "github.com/xtls/xray-core/core"

	"github.com/eycorsican/go-tun2socks/core"
	"github.com/xtls/xray-core/common/bytespool"
	"github.com/xxf098/go-tun2socks-build/pool"
)

type tcpHandler struct {
	ctx context.Context
	v   *xcore.Instance
}

func (h *tcpHandler) relay(lhs net.Conn, rhs net.Conn) {
	go func() {
		buf := bytespool.Alloc(pool.BufSize)
		io.CopyBuffer(rhs, lhs, buf)
		bytespool.Free(buf)
		lhs.Close()
		rhs.Close()
	}()
	buf := bytespool.Alloc(pool.BufSize)
	io.CopyBuffer(lhs, rhs, buf)
	bytespool.Free(buf)
	lhs.Close()
	rhs.Close()
}

func NewTCPHandler(ctx context.Context, instance *xcore.Instance) core.TCPConnHandler {
	return &tcpHandler{
		ctx: ctx,
		v:   instance,
	}
}

func (h *tcpHandler) Handle(conn net.Conn, target *net.TCPAddr) error {
	dest := xnet.DestinationFromAddr(target)
	sid := xsession.NewID()
	ctx := xsession.ContextWithID(h.ctx, sid)
	c, err := xcore.Dial(ctx, h.v, dest)
	if err != nil {
		return fmt.Errorf("dial V proxy connection failed: %v", err)
	}
	go h.relay(conn, c)
	return nil
}
