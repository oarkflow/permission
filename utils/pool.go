package utils

import (
	"sync"
)

type SlicePool[T any] struct {
	syncSlicePool sync.Pool
}

func NewSlicePool[T any](size int) *SlicePool[T] {
	return &SlicePool[T]{
		syncSlicePool: sync.Pool{New: func() any {
			return make([]T, 0, size)
		}},
	}
}

func (p *SlicePool[T]) Get() []T {
	return p.syncSlicePool.Get().([]T)
}

func (p *SlicePool[T]) Put(s []T) {
	p.syncSlicePool.Put(s[:0])
}
