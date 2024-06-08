package maps

import (
	"sync"
)

type SafeMap[K comparable, V any] struct {
	mu   sync.RWMutex
	data map[K]V
}

func (sm *SafeMap[K, V]) Delete(key K) {
	sm.mu.Lock()
	sm.mu.Unlock()
	delete(sm.data, key)
}

func (sm *SafeMap[K, V]) Del(keys ...K) {
	for _, key := range keys {
		sm.Delete(key)
	}
}

func (sm *SafeMap[K, V]) Get(key K) (value V, ok bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	value, ok = sm.data[key]
	return
}

func (sm *SafeMap[K, V]) Set(key K, value V) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.data[key] = value
}

func (sm *SafeMap[K, V]) ForEach(f func(K, V) bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	for k, v := range sm.data {
		if !f(k, v) {
			break
		}
	}
}

func (sm *SafeMap[K, V]) Len() uintptr {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return uintptr(len(sm.data))
}

func New[K comparable, V any]() *SafeMap[K, V] {
	return &SafeMap[K, V]{
		data: make(map[K]V),
	}
}
