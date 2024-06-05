package main

import (
	"fmt"
	"runtime"

	"github.com/oarkflow/permission/loader"
)

func main() {
	load := loader.New(loader.Config{
		TenantKey:    "company_id",
		NamespaceKey: "service_id",
		ScopeKey:     "entity_id",
		RoleKey:      "role_id",
		ResourceKey:  "route_uri",
		ActionKey:    "route_method",
	})
	stats()
	authorizer, err := load.LoadFile("company_permissions.json")
	if err != nil {
		panic(err)
	}
	stats()
	fmt.Println("Tenant", len(authorizer.Tenants()))
	fmt.Println("Namespace", len(authorizer.Namespaces()))
	fmt.Println("Scopes", len(authorizer.Scopes()))
	fmt.Println("Roles", len(authorizer.Roles()))
	fmt.Println("Attributes", len(authorizer.Attributes()))
}

func stats() {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	fmt.Printf("Total allocated memory: %f MB\n", float64(mem.TotalAlloc)/(1<<20))
	fmt.Printf("Number of memory allocations: %d\n", mem.Mallocs)
}

// {
//"entity":"facility",
//"model":"",
//"entity_id_placeholder":"",
//"route_uri":"/users/roles/assign",
//"route_method":"POST",
//"company_id":9,
//"service_id":2,
//"role_id":18,
//"entity_id":41
//}
