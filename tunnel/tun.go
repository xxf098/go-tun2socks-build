package tunnel

import (
	"errors"
	"io"
	"os"
	"syscall"
)

type Interface struct {
	io.ReadWriteCloser
	ReadCh chan []byte
	StopCh chan bool
}

func OpenTunDevice(tunFd int) (*Interface, error) {
	if tunFd < 0 {
		return nil, errors.New("must provide a valid TUN file descriptor")
	}
	file := os.NewFile(uintptr(tunFd), "tun")
	_ = syscall.SetNonblock(tunFd, true)
	tunDev := &Interface{
		ReadWriteCloser: file,
		StopCh:          make(chan bool, 2),
		ReadCh:          make(chan []byte, 2000),
	}
	return tunDev, nil
}
