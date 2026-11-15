package shadowsocksserver

import "sync"

// Borrow buffers only while writing a record, never while waiting for the next
// read. Idle connections therefore do not each retain a maximum-sized buffer.
var streamWritePools = [...]sync.Pool{{}, {}, {}, {}}
var streamWriteSizes = [...]int{(4 << 10) + 64, (16 << 10) + 64, (32 << 10) + 64, (64 << 10) + 64}

type streamWriteBuffer struct {
	data  []byte
	class int
}

func borrowStreamWriteBuffer(size int) *streamWriteBuffer {
	for class, capacity := range streamWriteSizes {
		if size > capacity {
			continue
		}
		if buffer, ok := streamWritePools[class].Get().(*streamWriteBuffer); ok {
			buffer.data = buffer.data[:size]
			return buffer
		}
		return &streamWriteBuffer{data: make([]byte, size, capacity), class: class}
	}
	return &streamWriteBuffer{data: make([]byte, size), class: -1}
}

func (buffer *streamWriteBuffer) release() {
	clear(buffer.data)
	if buffer.class >= 0 {
		streamWritePools[buffer.class].Put(buffer)
	}
}
