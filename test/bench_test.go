package test

import (
	"testing"

	"github.com/oarkflow/permission"
	v2 "github.com/oarkflow/permission/v2"
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

func BenchmarkMain(b *testing.B) {
	authorizer := permission.New()
	addAttributes(authorizer)
	tenantA := authorizer.AddTenant(permission.NewTenant("TenantA"))
	tenantB := authorizer.AddTenant(permission.NewTenant("TenantB"))
	namespace := authorizer.AddNamespace(permission.NewNamespace("NamespaceA"))
	tenantA.AddNamespace(namespace)
	tenantA.AddDescendant(tenantB)
	// tenantA.SetDefaultNamespace(namespace.ID())
	coder, qa, suspendManager, _ := myRoles(authorizer)
	tenantA.AddRole(coder, qa, suspendManager)
	e29 := authorizer.AddScope(permission.NewScope("EntityA"))
	tenantA.AddScopes(e29)

	principalA := authorizer.AddPrincipal(permission.NewPrincipal("principalA"))

	tenantA.AddPrincipal(principalA.ID(), coder.ID())
	tenantA.AssignScopesToPrincipal(principalA.ID(), e29.ID())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MainTest(authorizer)
	}
}
