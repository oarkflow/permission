package main

import (
	"fmt"

	"github.com/oarkflow/permission"
	"github.com/oarkflow/permission/trie"
)

func main() {
	t := trie.New(permission.FilterFunc)
	tp1 := &permission.Data{
		TenantID:             "tenant1",
		PrincipalID:          "principal1",
		RoleID:               "role1",
		NamespaceID:          "namespace1",
		ScopeID:              "scope1",
		CanManageDescendants: true,
	}
	tp3 := &permission.Data{
		TenantID:    "tenant1",
		PrincipalID: "principal3",
	}

	tp2 := &permission.Data{
		TenantID:             "tenant2",
		PrincipalID:          "principal2",
		RoleID:               "role2",
		NamespaceID:          "namespace2",
		ScopeID:              "scope2",
		CanManageDescendants: false,
	}

	tp4 := &permission.Data{
		TenantID:             "tenant2",
		PrincipalID:          "principal2",
		RoleID:               "role1",
		NamespaceID:          "namespace2",
		ScopeID:              "scope2",
		CanManageDescendants: false,
	}

	t.Insert(tp1)
	t.Insert(tp2)
	t.Insert(tp3)
	t.Insert(tp4)

	// Search for tenant principals with specific fields
	tpToSearch := &permission.Data{RoleID: "role1", TenantID: "tenant2"}
	results := t.Search(tpToSearch)
	for _, result := range results {
		fmt.Printf("Found: %+v\n", result)
	}
}
