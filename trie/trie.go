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

func NewNode[T any]() *Node[T] {
	return &Node[T]{child: maps.NewMap[any, *Node[T]]()}
}

func (node *Node[T]) addChild(field any) *Node[T] {
	if field == nil {
		return nil
	}
	if n, exists := node.child.Get(field); exists {
		return n
	}
	n := NewNode[T]()
	node.child.Set(field, n)
	return n
}

func (node *Node[T]) getChild(field any) (*Node[T], bool) {
	if field == nil {
		return nil, false
	}
	n, exists := node.child.Get(field)
	return n, exists
}

type Trie[T DataProps] struct {
	root         *Node[T]
	match        SearchFunc[T]
	keyExtractor KeyExtractor[T]
}

func New[T any](match SearchFunc[T], keyExtractor KeyExtractor[T]) *Trie[T] {
	return &Trie[T]{
		root:         NewNode[T](),
		match:        match,
		keyExtractor: keyExtractor,
	}
}

func (t *Trie[T]) Insert(data *T) {
	node := t.root
	keys := t.keyExtractor(data)

	for _, key := range keys {
		if key == nil {
			continue
		}
		child, _ := node.getChild(key)
		if child == nil {
			child = node.addChild(key)
		}
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
	rs := t.search(filter, callback)
	if len(rs) > 0 {
		return rs[0]
	}
	return nil
}

func (t *Trie[T]) Search(filter *T) []*T {
	return t.search(filter, t.match)
}

func (t *Trie[T]) search(filter *T, callback SearchFunc[T], first ...bool) []*T {
	results := &[]*T{}
	t.searchIterative(filter, callback, results, first...)
	return *results
}

func (t *Trie[T]) Data() []*T {
	return t.search(nil, func(f *T, n *T) bool { return true })
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
		node.child.ForEach(func(_ any, child *Node[T]) bool {
			stack = append(stack, child)
			return true
		})
	}
}
