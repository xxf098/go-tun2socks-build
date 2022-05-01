package lite

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/eycorsican/go-tun2socks/core"
	"github.com/xtls/xray-core/common/bytespool"
	"github.com/xxf098/go-tun2socks-build/pool"

	N "github.com/xxf098/lite-proxy/common/net"
	C "github.com/xxf098/lite-proxy/constant"
	"github.com/xxf098/lite-proxy/outbound"
	"github.com/xxf098/lite-proxy/tunnel"
)

type tcpHandler struct {
	ctx    context.Context
	client outbound.Dialer
}

// TODO: refactor
func (h *tcpHandler) relay(lhs net.Conn, rhs net.Conn) {
	go func() {
		buf := bytespool.Alloc(pool.BufSize)
		_, err := io.CopyBuffer(N.WriteOnlyWriter{Writer: lhs}, N.ReadOnlyReader{Reader: rhs}, buf)
		if err != nil {
			fmt.Printf("relay: %s\n", err)
		}
		bytespool.Free(buf)
		lhs.Close()
		rhs.Close()
	}()
	buf := bytespool.Alloc(pool.BufSize)
	// io.CopyBuffer(lhs, rhs, buf)
	_, err := io.CopyBuffer(N.WriteOnlyWriter{Writer: rhs}, N.ReadOnlyReader{Reader: lhs}, buf)
	if err != nil {
		fmt.Printf("relay: %s\n", err)
	}
	bytespool.Free(buf)
	lhs.Close()
	rhs.Close()
}

func NewTCPHandler(ctx context.Context, client outbound.Dialer) core.TCPConnHandler {
	return &tcpHandler{
		ctx:    ctx,
		client: client,
	}
}

func (h *tcpHandler) Handle(conn net.Conn, target *net.TCPAddr) error {
	addr, err := tunnel.NewAddressFromAddr(target.Network(), target.String())
	if err != nil {
		return err
	}
	meta := &C.Metadata{
		NetWork:  C.TCP,
		Type:     0,
		SrcPort:  "",
		AddrType: int(addr.AddressType),
		DstPort:  fmt.Sprintf("%d", addr.Port),
		DstIP:    addr.IP,
	}
	c, err := h.client.DialContext(h.ctx, meta)
	if err != nil {
		return fmt.Errorf("dial V proxy connection failed: %v", err)
	}
	go h.relay(conn, c)
	return nil
}
