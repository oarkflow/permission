package test

import (
	"testing"

	v2 "github.com/oarkflow/permission"
)

func BenchmarkV2(b *testing.B) {
	authorizer := v2.New()
	v2addAttributes(authorizer)
	tenantA := authorizer.AddTenant(v2.NewTenant("TenantA"))
	tenantB := authorizer.AddTenant(v2.NewTenant("TenantB"))
	namespace := authorizer.AddNamespace(v2.NewNamespace("NamespaceA"))
	tenantA.AddNamespaces(namespace)
	tenantA.AddDescendant(tenantB)
	// tenantA.SetDefaultNamespace(namespace.ID())
	coder, qa, suspendManager, _ := v2myRoles(authorizer)
	tenantA.AddRoles(coder, qa, suspendManager)
	e29 := authorizer.AddScope(v2.NewScope("EntityA"))
	tenantA.AddScopes(e29)

	principalA := authorizer.AddPrincipal(v2.NewPrincipal("principalA"))

	tenantA.AddPrincipal(principalA.ID(), coder.ID())
	tenantA.AssignScopesToPrincipal(principalA.ID(), e29.ID())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		V2Test(authorizer)
	}
}
