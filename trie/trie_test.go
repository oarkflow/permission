package trie_test

import (
	"testing"

	"github.com/oarkflow/permission/trie"
)

func BenchmarkInsert(b *testing.B) {
	t := trie.New()
	tp := &trie.Data{
		TenantID:             "tenant1",
		PrincipalID:          "principal1",
		RoleID:               "role1",
		NamespaceID:          "namespace1",
		ScopeID:              "scope1",
		CanManageDescendants: true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t.Insert(tp)
	}
}

func BenchmarkSearch(b *testing.B) {
	t := trie.New()
	tp := &trie.Data{
		TenantID:             "tenant1",
		PrincipalID:          "principal1",
		RoleID:               "role1",
		NamespaceID:          "namespace1",
		ScopeID:              "scope1",
		CanManageDescendants: true,
	}
	t.Insert(tp)

	filter := trie.Data{TenantID: "tenant1", PrincipalID: "principal1", RoleID: "role1", NamespaceID: "namespace1", ScopeID: "scope1", CanManageDescendants: true}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = t.Search(filter, true)
	}
}
