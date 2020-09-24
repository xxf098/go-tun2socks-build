package pool

import (
	"sync"
)

var pool *sync.Pool

const BufSize = 20 * 1024

func NewBytes(size int) []byte {
	if size <= BufSize {
		return pool.Get().([]byte)
	} else {
		return make([]byte, size)
	}
}

func FreeBytes(b []byte) {
	b = b[0:cap(b)] // restore slice
	if cap(b) >= BufSize {
		pool.Put(b)
	}
}

func init() {
	pool = &sync.Pool{
		New: func() interface{} {
			// The Pool's New function should generally only return pointer
			// types, since a pointer can be put into the return interface
			// value without an allocation:
			return make([]byte, BufSize)
		},
	}
}
