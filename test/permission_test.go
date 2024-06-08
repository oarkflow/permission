package test

import (
	"testing"

	v2 "github.com/oarkflow/permission"

	"github.com/oarkflow/permission/v1"
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
	authorizer := v1.New()
	addAttributes(authorizer)
	tenantA := authorizer.AddTenant(v1.NewTenant("TenantA"))
	tenantB := authorizer.AddTenant(v1.NewTenant("TenantB"))
	namespace := authorizer.AddNamespace(v1.NewNamespace("NamespaceA"))
	tenantA.AddNamespace(namespace)
	tenantA.AddDescendent(tenantB)
	// tenantA.SetDefaultNamespace(namespace.ID())
	coder, qa, suspendManager, _ := myRoles(authorizer)
	tenantA.AddRole(coder, qa, suspendManager)
	e29 := authorizer.AddScope(v1.NewScope("EntityA"))
	tenantA.AddScopes(e29)

	principalA := authorizer.AddPrincipal(v1.NewPrincipal("principalA"))

	tenantA.AddPrincipal(principalA.ID(), coder.ID())
	tenantA.AssignScopesToPrincipal(principalA.ID(), e29.ID())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MainTest(authorizer)
	}
}

func V2Test(authorizer *v2.RoleManager) {
	authorizer.Authorize("principalA",
		v2.WithTenant("TenantA"),
		v2.WithNamespace("NamespaceA"),
		v2.WithScope("EntityA"),
	)
}

func v2coderPermissions() []*v2.Attribute {
	return []*v2.Attribute{
		v2.NewAttribute("/coding/:wid/:eid/start-coding", "POST"),
		v2.NewAttribute("/coding/:wid/open", "GET"),
		v2.NewAttribute("/coding/:wid/in-progress", "GET"),
		v2.NewAttribute("/coding/:wid/:eid/review", "POST"),
	}
}

func v2qaPermissions() []*v2.Attribute {
	return []*v2.Attribute{
		v2.NewAttribute("/coding/:wid/:eid/start-qa", "POST"),
		v2.NewAttribute("/coding/:wid/qa", "GET"),
		v2.NewAttribute("/coding/:wid/qa-in-progress", "GET"),
		v2.NewAttribute("/coding/:wid/:eid/qa-review", "POST"),
	}
}

func v2suspendManagerPermissions() []*v2.Attribute {
	return []*v2.Attribute{
		v2.NewAttribute("/coding/:wid/suspended", "GET"),
		v2.NewAttribute("/coding/:wid/:eid/release-suspend", "POST"),
		v2.NewAttribute("/coding/:wid/:eid/request-abandon", "POST"),
	}
}

func v2adminManagerPermissions() []*v2.Attribute {
	return []*v2.Attribute{
		v2.NewAttribute("/admin/principal/add", "POST"),
		v2.NewAttribute("/admin/principal/edit", "PUT"),
	}
}

func v2myRoles(authorizer *v2.RoleManager) (coder *v2.Role, qa *v2.Role, suspendManager *v2.Role, admin *v2.Role) {
	coder = authorizer.AddRole(v2.NewRole("coder"))
	qa = authorizer.AddRole(v2.NewRole("qa"))
	suspendManager = authorizer.AddRole(v2.NewRole("suspend-manager"))
	admin = authorizer.AddRole(v2.NewRole("admin"))
	err := authorizer.AddPermissionsToRole(coder.ID(), "backend", v2coderPermissions()...)
	if err != nil {
		panic(err)
	}
	err = authorizer.AddPermissionsToRole(qa.ID(), "backend", v2qaPermissions()...)
	if err != nil {
		panic(err)
	}
	err = authorizer.AddPermissionsToRole(suspendManager.ID(), "backend", v2suspendManagerPermissions()...)
	if err != nil {
		panic(err)
	}
	err = authorizer.AddPermissionsToRole(admin.ID(), "page", v2adminManagerPermissions()...)
	if err != nil {
		panic(err)
	}
	err = admin.AddDescendant(coder, qa, suspendManager)
	if err != nil {
		panic(err)
	}
	return
}

func v2addAttributes(authorizer *v2.RoleManager) {
	var attrs []*v2.Attribute
	attrs = append(attrs, v2qaPermissions()...)
	attrs = append(attrs, v2coderPermissions()...)
	attrs = append(attrs, v2suspendManagerPermissions()...)
	backendGroup := v2.NewAttributeGroup("backend")
	backendGroup.AddAttributes(attrs...)
	pageGroup := v2.NewAttributeGroup("page")
	pageGroup.AddAttributes(v2adminManagerPermissions()...)
	authorizer.AddAttributeGroups(backendGroup, pageGroup)
}

func MainTest(authorizer *v1.RoleManager) {

	authorizer.Authorize("principalA",
		v1.WithTenant("TenantA"),
		v1.WithNamespace("NamespaceA"),
		v1.WithScope("EntityA"),
	)

}

func coderPermissions() []*v1.Attribute {
	return []*v1.Attribute{
		v1.NewAttribute("/coding/:wid/:eid/start-coding", "POST"),
		v1.NewAttribute("/coding/:wid/open", "GET"),
		v1.NewAttribute("/coding/:wid/in-progress", "GET"),
		v1.NewAttribute("/coding/:wid/:eid/review", "POST"),
	}
}

func qaPermissions() []*v1.Attribute {
	return []*v1.Attribute{
		v1.NewAttribute("/coding/:wid/:eid/start-qa", "POST"),
		v1.NewAttribute("/coding/:wid/qa", "GET"),
		v1.NewAttribute("/coding/:wid/qa-in-progress", "GET"),
		v1.NewAttribute("/coding/:wid/:eid/qa-review", "POST"),
	}
}

func suspendManagerPermissions() []*v1.Attribute {
	return []*v1.Attribute{
		v1.NewAttribute("/coding/:wid/suspended", "GET"),
		v1.NewAttribute("/coding/:wid/:eid/release-suspend", "POST"),
		v1.NewAttribute("/coding/:wid/:eid/request-abandon", "POST"),
	}
}

func adminManagerPermissions() []*v1.Attribute {
	return []*v1.Attribute{
		v1.NewAttribute("/admin/principal/add", "POST"),
		v1.NewAttribute("/admin/principal/edit", "PUT"),
	}
}

func myRoles(authorizer *v1.RoleManager) (coder *v1.Role, qa *v1.Role, suspendManager *v1.Role, admin *v1.Role) {
	coder = authorizer.AddRole(v1.NewRole("coder"))
	qa = authorizer.AddRole(v1.NewRole("qa"))
	suspendManager = authorizer.AddRole(v1.NewRole("suspend-manager"))
	admin = authorizer.AddRole(v1.NewRole("admin"))
	err := authorizer.AddPermissionsToRole(coder.ID(), "backend", coderPermissions()...)
	if err != nil {
		panic(err)
	}
	err = authorizer.AddPermissionsToRole(qa.ID(), "backend", qaPermissions()...)
	if err != nil {
		panic(err)
	}
	err = authorizer.AddPermissionsToRole(suspendManager.ID(), "backend", suspendManagerPermissions()...)
	if err != nil {
		panic(err)
	}
	err = authorizer.AddPermissionsToRole(admin.ID(), "page", adminManagerPermissions()...)
	if err != nil {
		panic(err)
	}
	err = admin.AddDescendent(coder, qa, suspendManager)
	if err != nil {
		panic(err)
	}
	return
}

func addAttributes(authorizer *v1.RoleManager) {
	var attrs []*v1.Attribute
	attrs = append(attrs, qaPermissions()...)
	attrs = append(attrs, coderPermissions()...)
	attrs = append(attrs, suspendManagerPermissions()...)
	backendGroup := v1.NewAttributeGroup("backend")
	backendGroup.AddAttributes(attrs...)
	pageGroup := v1.NewAttributeGroup("page")
	pageGroup.AddAttributes(adminManagerPermissions()...)
	authorizer.AddAttributeGroups(backendGroup, pageGroup)
}
