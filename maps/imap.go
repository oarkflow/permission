package maps

type IMap[K comparable, V any] interface {
	Del(keys ...K)
	Get(key K) (value V, ok bool)
	Set(key K, value V)
	ForEach(lambda func(K, V) bool)
	Len() uintptr
}
