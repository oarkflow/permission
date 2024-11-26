package trie

import (
	maps "github.com/oarkflow/xsync"
)

type DataProps any

type SearchFunc[T DataProps] func(filter *T, row *T) bool

type KeyExtractor[T DataProps] func(data *T) []any

type Node[T DataProps] struct {
	child maps.IMap[any, *Node[T]]
	isEnd bool
	data  *T
}

func NewNode[T DataProps]() *Node[T] {
	return &Node[T]{child: maps.NewMap[any, *Node[T]]()}
}

func (node *Node[T]) addChild(key any) (*Node[T], bool) {
	if key == nil {
		return nil, false
	}
	if n, exists := node.child.Get(key); exists {
		return n, true
	}
	n := NewNode[T]()
	node.child.Set(key, n)
	return n, false
}

func (node *Node[T]) getChild(key any) (*Node[T], bool) {
	if key == nil {
		return nil, false
	}
	n, exists := node.child.Get(key)
	return n, exists
}

type Trie[T DataProps] struct {
	root         *Node[T]
	match        SearchFunc[T]
	keyExtractor KeyExtractor[T]
}

func New[T DataProps](match SearchFunc[T], keyExtractor KeyExtractor[T]) *Trie[T] {
	if match == nil || keyExtractor == nil {
		panic("match and keyExtractor functions cannot be nil")
	}
	return &Trie[T]{
		root:         NewNode[T](),
		match:        match,
		keyExtractor: keyExtractor,
	}
}

func (t *Trie[T]) Insert(data *T) {
	if data == nil {
		return
	}
	node := t.root
	keys := t.keyExtractor(data)
	if keys == nil {
		panic("keyExtractor returned nil keys")
	}

	for _, key := range keys {
		if key == nil {
			continue
		}
		child, _ := node.addChild(key)
		node = child
	}

	node.isEnd = true
	node.data = data
}

func (t *Trie[T]) First(filter *T) *T {
	return t.first(filter, t.match)
}

func (t *Trie[T]) FirstFunc(filter *T, callback SearchFunc[T]) *T {
	return t.first(filter, callback)
}

func (t *Trie[T]) first(filter *T, callback SearchFunc[T]) *T {
	results := t.search(filter, callback, true)
	if len(results) > 0 {
		return results[0]
	}
	return nil
}

func (t *Trie[T]) Search(filter *T) []*T {
	return t.search(filter, t.match)
}

func (t *Trie[T]) search(filter *T, callback SearchFunc[T], stopAfterFirst ...bool) []*T {
	var results []*T
	t.searchIterative(filter, callback, &results, stopAfterFirst...)
	return results
}

func (t *Trie[T]) SearchFunc(filter *T, callback SearchFunc[T]) []*T {
	return t.search(filter, callback)
}

func (t *Trie[T]) searchIterative(filter *T, callback SearchFunc[T], results *[]*T, stopAfterFirst ...bool) {
	stack := make([]*Node[T], 0, 64) // Increased initial capacity for optimization
	stack = append(stack, t.root)
	stop := len(stopAfterFirst) > 0 && stopAfterFirst[0]

	for len(stack) > 0 {
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if node.isEnd && callback(filter, node.data) {
			*results = append(*results, node.data)
			if stop {
				return
			}
		}

		node.child.ForEach(func(_ any, child *Node[T]) bool {
			stack = append(stack, child)
			return true
		})
	}
}

func (t *Trie[T]) Data() []*T {
	// Use a no-op search function to retrieve all data
	return t.search(nil, func(_ *T, _ *T) bool { return true })
}
