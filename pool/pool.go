package pool

import (
	"context"
	"io"
	"log"
	"os"
	"syscall"

	vbytespool "v2ray.com/core/common/bytespool"
)

const BufSize = 20 * 1024
const MTU = 2 * 1024

type Interface struct {
	io.ReadWriteCloser
	WriteCh chan []byte
	ReadCh  chan []byte
	StopCh  chan bool
}

func (tunDev *Interface) HandleOuput(data []byte) (int, error) {
	buf := vbytespool.Alloc(int32(len(data)))
	l := copy(buf, data)
	tunDev.WriteCh <- buf
	return l, nil
}

func OpenTunDevice(tunFd int) (*Interface, error) {
	file := os.NewFile(uintptr(tunFd), "tun")
	_ = syscall.SetNonblock(tunFd, true)
	tunDev := &Interface{
		ReadWriteCloser: file,
		StopCh:          make(chan bool, 2),
		WriteCh:         make(chan []byte, 1200),
		ReadCh:          make(chan []byte, 1200),
	}
	return tunDev, nil
}

func (tunDev *Interface) Run(ctx context.Context) {
	// writer
	go func(ctx context.Context) {
		for {
			select {
			case <-ctx.Done():
				return
			case <-tunDev.StopCh:
				return
			case buf := <-tunDev.WriteCh:
				tunDev.Write(buf)
				vbytespool.Free(buf)
			}
		}
	}(ctx)
	// reader
	for {
		data := vbytespool.Alloc(MTU)
		n, err := tunDev.Read(data)
		if err != nil && err != io.EOF {
			return
		}
		select {
		case tunDev.ReadCh <- data[:n]:
			break
		case <-ctx.Done():
			return
		case <-tunDev.StopCh:
			return
		default:
			vbytespool.Free(data[:cap(data)])
		}
	}
}

func (tunDev *Interface) Stop() {
	err := tunDev.Close()
	if err != nil {
		log.Printf("close tun: %v", err)
	}
	tunDev.StopCh <- true
}

func NewBytes(size int) []byte {
	// if size <= BufSize {
	// 	return pool.Get().([]byte)
	// } else {
	// 	return make([]byte, size)
	// }
	return defaultAllocator.Get(size)
}

func FreeBytes(b []byte) {
	// b = b[0:cap(b)] // restore slice
	// if cap(b) >= BufSize {
	// 	pool.Put(b)
	// }
	_ = defaultAllocator.Put(b)
}

// func init() {
// 	pool = &sync.Pool{
// 		New: func() interface{} {

// 			return make([]byte, BufSize)
// 		},
// 	}
// }
