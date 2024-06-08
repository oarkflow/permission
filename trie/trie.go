package trie

import (
	"reflect"
	"sync"
)

type DataProps any

type SearchFunc[T DataProps] func(filter *T, row *T) bool

func IsNil(value any) bool {
	return value == nil
}

func MatchesFilter(value, filter any) bool {
	return !IsNil(filter) && value == filter
}

func FilterByFields[T DataProps](filter *T, row *T, fields ...func(*T) any) bool {
	for _, field := range fields {
		if IsNil(field(row)) || !MatchesFilter(field(row), field(filter)) {
			return false
		}
	}
	return true
}

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

func (t *Trie[T]) Insert(tp *T) {
	node := t.root
	v := reflect.ValueOf(*tp)
	fields := make([]any, 0)
	switch v.Kind() {
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			fields = append(fields, v.Field(i).Interface())
		}
	case reflect.Map:
		for _, key := range v.MapKeys() {
			fields = append(fields, v.MapIndex(key).Interface())
		}
	}
	for _, field := range fields {
		child, _ := node.getChild(field)
		if child == nil {
			child = node.addChild(field)
		}
		node = child
	}
	node.isEnd = true
	node.data = tp
}

func (t *Trie[T]) Data() []*T {
	results := t.dataSlice.Get().(*[]*T)
	defer t.dataSlice.Put(results)
	*results = (*results)[:0]
	t.searchRecursiveFunc(t.root, nil, func(f *T, n *T) bool { return true }, results)
	return *results
}

func (t *Trie[T]) Search(filter *T) []*T {
	results := t.dataSlice.Get().(*[]*T)
	defer t.dataSlice.Put(results)
	*results = (*results)[:0]
	t.searchRecursiveFunc(t.root, filter, t.match, results)
	return *results
}

func (t *Trie[T]) SearchFunc(filter *T, callback SearchFunc[T]) []*T {
	results := t.dataSlice.Get().(*[]*T)
	defer t.dataSlice.Put(results)
	*results = (*results)[:0]
	t.searchRecursiveFunc(t.root, filter, callback, results)
	return *results
}

func (t *Trie[T]) searchRecursiveFunc(node *Node[T], filter *T, callback SearchFunc[T], results *[]*T) {
	if node.isEnd && callback(filter, node.data) {
		*results = append(*results, node.data)
	}
	for _, child := range node.child {
		t.searchRecursiveFunc(child, filter, callback, results)
	}
}

func (t *Trie[T]) First(filter T) *T {
	results := t.dataSlice.Get().(*[]*T)
	defer t.dataSlice.Put(results)
	*results = (*results)[:0]
	t.firstRecursiveFunc(t.root, &filter, t.match, results)
	if len(*results) > 0 {
		return (*results)[0]
	}
	return nil
}

func (t *Trie[T]) FirstFunc(filter T, callback SearchFunc[T]) *T {
	results := t.dataSlice.Get().(*[]*T)
	defer t.dataSlice.Put(results)
	*results = (*results)[:0]
	t.firstRecursiveFunc(t.root, &filter, callback, results)
	if len(*results) > 0 {
		return (*results)[0]
	}
	return nil
}

func (t *Trie[T]) firstRecursiveFunc(node *Node[T], filter *T, callback SearchFunc[T], results *[]*T) {
	if node.isEnd && callback(filter, node.data) {
		*results = append(*results, node.data)
	}
	if len(*results) == 1 {
		return
	}
	for _, child := range node.child {
		t.firstRecursiveFunc(child, filter, callback, results)
		if len(*results) == 1 {
			break
		}
	}
}
