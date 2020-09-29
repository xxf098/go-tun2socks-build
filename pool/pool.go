package pool

const BufSize = 20 * 1024

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
