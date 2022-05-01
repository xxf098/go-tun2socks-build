package v2ray

import (
	"context"
	"fmt"
	"io"
	"net"

	vnet "github.com/xtls/xray-core/common/net"
	vsession "github.com/xtls/xray-core/common/session"
	vcore "github.com/xtls/xray-core/core"

	"github.com/eycorsican/go-tun2socks/core"
	"github.com/xtls/xray-core/common/bytespool"
	"github.com/xxf098/go-tun2socks-build/pool"
	N "github.com/xxf098/lite-proxy/common/net"
)

type tcpHandler struct {
	ctx context.Context
	v   *vcore.Instance
}

// sniff address remove google 80
func (h *tcpHandler) relay(lhs net.Conn, rhs net.Conn, addr string) {
	go func() {
		buf := bytespool.Alloc(pool.BufSize)
		_, err := io.CopyBuffer(N.WriteOnlyWriter{Writer: lhs}, N.ReadOnlyReader{Reader: rhs}, buf)
		if err != nil {
			fmt.Printf("relay: lhs %s, %s\n", addr, err)
		}
		bytespool.Free(buf)
		lhs.Close()
		rhs.Close()
	}()
	buf := bytespool.Alloc(pool.BufSize)
	// io.CopyBuffer(lhs, rhs, buf)
	_, err := io.CopyBuffer(N.WriteOnlyWriter{Writer: rhs}, N.ReadOnlyReader{Reader: lhs}, buf)
	if err != nil {
		fmt.Printf("relay: rhs %s, %s\n", addr, err)
	}
	bytespool.Free(buf)
	lhs.Close()
	rhs.Close()
}

func NewTCPHandler(ctx context.Context, instance *vcore.Instance) core.TCPConnHandler {
	return &tcpHandler{
		ctx: ctx,
		v:   instance,
	}
}

func (h *tcpHandler) Handle(conn net.Conn, target *net.TCPAddr) error {
	dest := vnet.DestinationFromAddr(target)
	sid := vsession.NewID()
	ctx := vsession.ContextWithID(h.ctx, sid)
	c, err := vcore.Dial(ctx, h.v, dest)
	if err != nil {
		return fmt.Errorf("dial V proxy connection failed: %v", err)
	}
	go h.relay(conn, c, target.String())
	return nil
}
