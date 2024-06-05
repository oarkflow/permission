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
	stats("BEFORE")
	authorizer, err := load.LoadFile("company_permissions.json")
	if err != nil {
		panic(err)
	}
	stats("AFTER")
	fmt.Println("Tenant", authorizer.TotalTenants())
	fmt.Println("Namespace", authorizer.TotalNamespaces())
	fmt.Println("Scopes", authorizer.TotalScopes())
	fmt.Println("Roles", authorizer.TotalRoles())
	fmt.Println("Attributes", authorizer.TotalAttributes())
}

func stats(suffix string) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	fmt.Printf("Total allocated memory: %f MB %s\n", float64(mem.TotalAlloc)/(1<<20), suffix)
	fmt.Printf("Number of memory allocations: %d %s\n", mem.Mallocs, suffix)
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
