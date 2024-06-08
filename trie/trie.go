package trie

import (
	"fmt"
	"sync"
)

type Data struct {
	TenantID             any
	NamespaceID          any
	ScopeID              any
	PrincipalID          any
	RoleID               any
	CanManageDescendants any
}

func (data Data) ToString() string {
	return fmt.Sprintf("%v-%v-%v-%v-%v-%v",
		data.TenantID, data.NamespaceID, data.ScopeID,
		data.PrincipalID, data.RoleID, data.CanManageDescendants)
}

type SearchFunc func(filer *Data, row *Data) bool

func IsNil(value any) bool {
	return value == nil
}

func MatchesFilter(value, filter any) bool {
	return !IsNil(filter) && value == filter
}

func FilterByFields(filter *Data, row *Data, fields ...func(*Data) any) bool {
	for _, field := range fields {
		if IsNil(field(row)) || !MatchesFilter(field(row), field(filter)) {
			return false
		}
	}
	return true
}

func AddData(tenantID, namespaceID, scopeID, principalID, roleID, canManageDescendants any) Data {
	return Data{
		TenantID:             tenantID,
		PrincipalID:          principalID,
		RoleID:               roleID,
		NamespaceID:          namespaceID,
		ScopeID:              scopeID,
		CanManageDescendants: canManageDescendants,
	}
}

type Node struct {
	mu    sync.RWMutex
	child map[any]*Node
	isEnd bool
	data  *Data
}

func (node *Node) addChild(field any) *Node {
	node.mu.Lock()
	defer node.mu.Unlock()
	n := &Node{child: make(map[any]*Node)}
	node.child[field] = n
	return n
}

func (node *Node) getChild(field any) (*Node, bool) {
	node.mu.Lock()
	defer node.mu.Unlock()
	n, exists := node.child[field]
	return n, exists
}

type Trie struct {
	root *Node
}

func New() *Trie {
	return &Trie{
		root: &Node{child: make(map[any]*Node)},
	}
}

func (t *Trie) Insert(tp *Data) {
	node := t.root
	fields := []any{tp.TenantID, tp.PrincipalID, tp.RoleID, tp.NamespaceID, tp.ScopeID, tp.CanManageDescendants}

	for _, field := range fields {
		child, exists := node.getChild(field)
		if !exists {
			child = node.addChild(field)
			node = child
		} else {
			node = child
		}
	}
	node.isEnd = true
	node.data = tp
}

func (t *Trie) Data() []*Data {
	results := dataSlice.Get()
	defer func() {
		dataSlice.Put(results[:0])
	}()
	t.searchRecursiveFunc(t.root, nil, func(f *Data, n *Data) bool { return true }, &results)
	return results
}

func (t *Trie) Search(filter Data) []*Data {
	results := dataSlice.Get()
	defer func() {
		dataSlice.Put(results[:0])
	}()
	t.searchRecursiveFunc(t.root, &filter, match, &results)
	return results
}

func (t *Trie) SearchFunc(filter Data, callback SearchFunc) []*Data {
	results := dataSlice.Get()
	defer func() {
		dataSlice.Put(results[:0])
	}()
	t.searchRecursiveFunc(t.root, &filter, callback, &results)
	return results
}

func (t *Trie) searchRecursiveFunc(node *Node, filter *Data, callback SearchFunc, results *[]*Data) {
	if node.isEnd && callback(filter, node.data) {
		*results = append(*results, node.data)
	}
	for _, child := range node.child {
		t.searchRecursiveFunc(child, filter, callback, results)
	}
}

func (t *Trie) First(filter Data) *Data {
	results := dataSlice.Get()
	defer func() {
		dataSlice.Put(results[:0])
	}()
	t.firstRecursiveFunc(t.root, &filter, match, &results)
	if len(results) > 0 {
		return results[0]
	}
	return nil
}

func (t *Trie) FirstFunc(filter Data, callback SearchFunc) *Data {
	results := dataSlice.Get()
	defer func() {
		dataSlice.Put(results[:0])
	}()
	t.firstRecursiveFunc(t.root, &filter, callback, &results)
	if len(results) > 0 {
		return results[0]
	}
	return nil
}

func (t *Trie) firstRecursiveFunc(node *Node, filter *Data, callback SearchFunc, results *[]*Data) {
	if node.isEnd && callback(filter, node.data) {
		*results = append(*results, node.data)
	}
	if len(*results) == 1 {
		return
	}
	for _, child := range node.child {
		t.firstRecursiveFunc(child, filter, callback, results)
	}
}

func match(filter *Data, node *Data) bool {
	if IsNil(filter.TenantID) && MatchesFilter(node.TenantID, filter.TenantID) {
		return false
	}
	if IsNil(filter.PrincipalID) && MatchesFilter(node.PrincipalID, filter.PrincipalID) {
		return false
	}
	if IsNil(filter.RoleID) && MatchesFilter(node.RoleID, filter.RoleID) {
		return false
	}
	if IsNil(filter.NamespaceID) && MatchesFilter(node.NamespaceID, filter.NamespaceID) {
		return false
	}
	if IsNil(filter.ScopeID) && MatchesFilter(node.ScopeID, filter.ScopeID) {
		return false
	}
	if IsNil(filter.CanManageDescendants) && filter.CanManageDescendants != node.CanManageDescendants {
		return false
	}
	return true
}
