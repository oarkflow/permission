package main

import (
	"fmt"

	"github.com/oarkflow/permission"
	"github.com/oarkflow/permission/trie"
)

func main() {
	t := trie.New(permission.FilterFunc)
	tp1 := &permission.Data{
		Tenant:            "tenant1",
		Principal:         "principal1",
		Role:              "role1",
		Namespace:         "namespace1",
		Scope:             "scope1",
		ManageDescendants: true,
	}
	tp3 := &permission.Data{
		Tenant:    "tenant1",
		Principal: "principal3",
	}

	tp2 := &permission.Data{
		Tenant:            "tenant2",
		Principal:         "principal2",
		Role:              "role2",
		Namespace:         "namespace2",
		Scope:             "scope2",
		ManageDescendants: false,
	}

	tp4 := &permission.Data{
		Tenant:            "tenant2",
		Principal:         "principal2",
		Role:              "role1",
		Namespace:         "namespace2",
		Scope:             "scope2",
		ManageDescendants: false,
	}

	t.Insert(tp1)
	t.Insert(tp2)
	t.Insert(tp3)
	t.Insert(tp4)

	// Search for tenant principals with specific fields
	tpToSearch := &permission.Data{Role: "role1", Tenant: "tenant2"}
	results := t.Search(tpToSearch)
	for _, result := range results {
		fmt.Printf("Found: %+v\n", result)
	}
}
