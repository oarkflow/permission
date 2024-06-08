package trie_test

import (
	"testing"

	"github.com/oarkflow/permission/trie"
)

func filterFunc(filter *map[string]any, node *map[string]any) bool {
	return true
}

func BenchmarkInsert(b *testing.B) {
	t := trie.New(filterFunc)
	tp := map[string]any{
		"test": "123",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t.Insert(&tp)
		t.Search(&map[string]any{"test": "123"})
	}
}
