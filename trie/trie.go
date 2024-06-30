package trie

import (
	"reflect"
	"sync"
)

type DataProps any

type SearchFunc[T DataProps] func(filter *T, row *T) bool

type Node[T DataProps] struct {
	mu    sync.RWMutex
	child map[any]*Node[T]
	isEnd bool
	data  *T
}

func (node *Node[T]) addChild(field any) *Node[T] {
	node.mu.Lock()
	defer node.mu.Unlock()
	if n, exists := node.child[field]; exists {
		return n
	}
	n := &Node[T]{child: make(map[any]*Node[T])}
	node.child[field] = n
	return n
}

func (node *Node[T]) getChild(field any) (*Node[T], bool) {
	node.mu.RLock()
	defer node.mu.RUnlock()
	n, exists := node.child[field]
	return n, exists
}

type Trie[T DataProps] struct {
	root      *Node[T]
	match     SearchFunc[T]
	dataSlice sync.Pool
}

func New[T DataProps](match SearchFunc[T]) *Trie[T] {
	return &Trie[T]{
		root: &Node[T]{child: make(map[any]*Node[T])},
		dataSlice: sync.Pool{
			New: func() any {
				return &[]*T{}
			},
		},
		match: match,
	}
}

func (t *Trie[T]) search(filter *T, callback SearchFunc[T], first ...bool) []*T {
	results := t.dataSlice.Get().(*[]*T)
	defer t.dataSlice.Put(results)
	*results = (*results)[:0]
	t.searchIterative(filter, callback, results, first...)
	return *results
}

func (t *Trie[T]) Data() []*T {
	return t.search(nil, func(f *T, n *T) bool { return true })
}

func (t *Trie[T]) Insert(tp *T) {
	node := t.root
	fields := reflect.ValueOf(*tp)
	switch reflect.ValueOf(*tp).Kind() {
	case reflect.Struct:
		for i := 0; i < fields.NumField(); i++ {
			field := fields.Field(i).Interface()
			child, _ := node.getChild(field)
			if child == nil {
				child = node.addChild(field)
			}
			node = child
		}
	case reflect.Map:
		for _, key := range fields.MapKeys() {
			field := fields.MapIndex(key).Interface()
			child, _ := node.getChild(field)
			if child == nil {
				child = node.addChild(field)
			}
			node = child
		}
	}
	node.isEnd = true
	node.data = tp
}

func (t *Trie[T]) First(filter *T) *T {
	return t.first(filter, t.match)
}

func (t *Trie[T]) FirstFunc(filter *T, callback SearchFunc[T]) *T {
	return t.first(filter, callback)
}

func (t *Trie[T]) first(filter *T, callback SearchFunc[T]) *T {
	rs := t.search(filter, callback)
	if len(rs) > 0 {
		return rs[0]
	}
	return nil
}

func (t *Trie[T]) Search(filter *T) []*T {
	return t.search(filter, t.match)
}

func (t *Trie[T]) SearchFunc(filter *T, callback SearchFunc[T]) []*T {
	return t.search(filter, callback)
}

func (t *Trie[T]) searchIterative(filter *T, callback SearchFunc[T], results *[]*T, first ...bool) {
	stack := []*Node[T]{t.root}
	for len(stack) > 0 {
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if node.isEnd && callback(filter, node.data) {
			*results = append(*results, node.data)
		}
		if len(first) > 0 && first[0] && len(*results) == 1 {
			return
		}
		for _, child := range node.child {
			stack = append(stack, child)
		}
	}
}
