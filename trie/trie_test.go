package trie_test

import (
	"testing"
	
	"github.com/oarkflow/permission/trie"
)

type Map map[string]any

func DataKeyExtractor(data *Map) []any {
	if data == nil {
		return []any{}
	}
	return []any{
		(*data)["test"],
	}
}

func filterFunc(filter *Map, node *Map) bool {
	return true
}

func BenchmarkInsert(b *testing.B) {
	t := trie.New(filterFunc, DataKeyExtractor)
	tp := Map{
		"test": "123",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t.Insert(&tp)
		t.Search(&Map{"test": "123"})
	}
}
