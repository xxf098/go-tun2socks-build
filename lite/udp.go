package lite

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	vsignal "github.com/xtls/xray-core/common/signal"
	vtask "github.com/xtls/xray-core/common/task"

	"github.com/eycorsican/go-tun2socks/common/log"
	"github.com/eycorsican/go-tun2socks/core"
	"github.com/xtls/xray-core/common/bytespool"
	"github.com/xxf098/go-tun2socks-build/pool"

	C "github.com/xxf098/lite-proxy/constant"
	"github.com/xxf098/lite-proxy/outbound"
	"github.com/xxf098/lite-proxy/tunnel"
)

type udpConnEntry struct {
	conn net.PacketConn

	// `ReadFrom` method of PacketConn given by V2Ray
	// won't return the correct remote address, we treat
	// all data receive from V2Ray are coming from the
	// same remote host, i.e. the `target` that passed
	// to `Connect`.
	target *net.UDPAddr

	updater vsignal.ActivityUpdater
}

type udpHandler struct {
	sync.Mutex

	ctx     context.Context
	v       outbound.Dialer
	conns   map[core.UDPConn]*udpConnEntry
	timeout time.Duration // Maybe override by V2Ray local policies for some conns.
}

func (h *udpHandler) fetchInput(conn core.UDPConn) {
	h.Lock()
	c, ok := h.conns[conn]
	h.Unlock()
	if !ok {
		return
	}

	buf := bytespool.Alloc(pool.BufSize)
	defer bytespool.Free(buf)

	for {
		n, _, err := c.conn.ReadFrom(buf)
		if err != nil && n <= 0 {
			h.Close(conn)
			conn.Close()
			return
		}
		c.updater.Update()
		_, err = conn.WriteFrom(buf[:n], c.target)
		if err != nil {
			h.Close(conn)
			conn.Close()
			return
		}
	}
}

func NewUDPHandler(ctx context.Context, instance outbound.Dialer, timeout time.Duration) core.UDPConnHandler {
	return &udpHandler{
		ctx:     ctx,
		v:       instance,
		conns:   make(map[core.UDPConn]*udpConnEntry, 16),
		timeout: timeout,
	}
}

func (h *udpHandler) Connect(conn core.UDPConn, target *net.UDPAddr) error {
	if target == nil {
		return errors.New("nil target is not allowed")
	}
	addr, err := tunnel.NewAddressFromAddr(target.Network(), target.String())
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	meta := &C.Metadata{
		NetWork: C.UDP,
		Type:    0,
		SrcPort: "",
		DstPort: fmt.Sprintf("%d", addr.Port),
		DstIP:   addr.IP,
	}

	pc, err := h.v.DialUDP(meta)
	if err != nil {
		cancel()
		return fmt.Errorf("dial V proxy connection failed: %v", err)
	}
	timer := vsignal.CancelAfterInactivity(ctx, cancel, h.timeout)
	h.Lock()
	h.conns[conn] = &udpConnEntry{
		conn:    pc,
		target:  target,
		updater: timer,
	}
	h.Unlock()
	fetchTask := func() error {
		h.fetchInput(conn)
		return nil
	}
	go func() {
		if err := vtask.Run(ctx, fetchTask); err != nil {
			pc.Close()
		}
	}()
	log.Infof("new proxy connection for target: %s:%s", target.Network(), target.String())
	return nil
}

func (h *udpHandler) ReceiveTo(conn core.UDPConn, data []byte, addr *net.UDPAddr) error {
	h.Lock()
	c, ok := h.conns[conn]
	h.Unlock()

	if ok {
		_, err := c.conn.WriteTo(data, addr)
		c.updater.Update()
		if err != nil {
			h.Close(conn)
			return fmt.Errorf("write remote failed: %v", err)
		}
		return nil
	} else {
		h.Close(conn)
		return fmt.Errorf("proxy connection %v->%v does not exists", conn.LocalAddr(), addr)
	}
}

func (h *udpHandler) Close(conn core.UDPConn) {
	h.Lock()
	defer h.Unlock()

	if c, found := h.conns[conn]; found {
		c.conn.Close()
	}
	delete(h.conns, conn)
}
