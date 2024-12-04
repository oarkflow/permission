package test

import (
	"testing"

	"github.com/oarkflow/permission"
	v2 "github.com/oarkflow/permission/v2"

	"github.com/oarkflow/permission/v1"
)

func BenchmarkV2(b *testing.B) {
	authorizer := v2.NewAuthorizer()

	rootTenant := v2.NewTenant("TenantA", "TenantA")
	rootTenant.AddScopes(v2.Scope{Name: "Entity29", Namespace: "NamespaceA"})
	childTenant := v2.NewTenant("TenantB", "TenantB")
	childTenant.AddScopes(v2.Scope{Name: "Entity30", Namespace: "NamespaceA"})
	rootTenant.AddChildTenant(childTenant)

	authorizer.AddTenant(rootTenant, childTenant)
	coder, _, _, _ := v2myRoles(authorizer)

	authorizer.AddUserRole(v2.UserRole{
		UserID:   "principalA",
		TenantID: rootTenant.ID,
		Role:     coder.Name,
	})
	r1 := v2.Request{UserID: "principalA", TenantID: rootTenant.ID, Scope: "Entity29", Resource: "/coding/1/2/start-coding", Method: "POST"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		authorizer.Authorize(r1)
	}
}

func v2myRoles(authorizer *v2.Authorizer) (coder *v2.Role, qa *v2.Role, suspendManager *v2.Role, admin *v2.Role) {
	coder = v2.NewRole("coder")
	coder.AddPermission(v2coderPermissions()...)
	authorizer.AddRole(coder)

	qa = v2.NewRole("qa")
	qa.AddPermission(v2qaPermissions()...)
	authorizer.AddRole(qa)

	suspendManager = v2.NewRole("suspend-manager")
	suspendManager.AddPermission(v2suspendManagerPermissions()...)
	authorizer.AddRole(suspendManager)

	admin = v2.NewRole("admin")
	admin.AddPermission(v2adminManagerPermissions()...)
	authorizer.AddRole(admin)

	authorizer.AddChildRole(admin.Name, coder.Name, qa.Name, suspendManager.Name)
	return
}

func v2coderPermissions() []v2.Permission {
	return []v2.Permission{
		{Resource: "/coding/:wid/:eid/start-coding", Method: "POST", Category: "backend"},
		{Resource: "/coding/:wid/open", Method: "GET", Category: "backend"},
		{Resource: "/coding/:wid/in-progress", Method: "GET", Category: "backend"},
		{Resource: "/coding/:wid/:eid/review", Method: "POST", Category: "backend"},
	}
}

func v2qaPermissions() []v2.Permission {
	return []v2.Permission{
		{Resource: "/coding/:wid/:eid/start-qa", Method: "POST", Category: "backend"},
		{Resource: "/coding/:wid/qa", Method: "GET", Category: "backend"},
		{Resource: "/coding/:wid/qa-in-progress", Method: "GET", Category: "backend"},
		{Resource: "/coding/:wid/:eid/qa-review", Method: "POST", Category: "backend"},
	}
}

func v2suspendManagerPermissions() []v2.Permission {
	return []v2.Permission{
		{Resource: "/coding/:wid/suspended", Method: "GET", Category: "backend"},
		{Resource: "/coding/:wid/:eid/release-suspend", Method: "POST", Category: "backend"},
		{Resource: "/coding/:wid/:eid/request-abandon", Method: "POST", Category: "backend"},
	}
}

func v2adminManagerPermissions() []v2.Permission {
	return []v2.Permission{
		{Resource: "/admin/principal/add", Method: "POST", Category: "backend"},
		{Resource: "/admin/principal/edit", Method: "PUT", Category: "backend"},
	}
}

func BenchmarkMain(b *testing.B) {
	authorizer := permission.New()
	mainaddAttributes(authorizer)
	tenantA := authorizer.AddTenant(permission.NewTenant("TenantA"))
	tenantB := authorizer.AddTenant(permission.NewTenant("TenantB"))
	namespace := authorizer.AddNamespace(permission.NewNamespace("NamespaceA"))
	tenantA.AddNamespaces(namespace)
	tenantA.AddDescendant(tenantB)
	// tenantA.SetDefaultNamespace(namespace.ID())
	coder, qa, suspendManager, _ := mainmyRoles(authorizer)
	tenantA.AddRoles(coder, qa, suspendManager)
	e29 := authorizer.AddScope(permission.NewScope("EntityA"))
	tenantA.AddScopes(e29)

	principalA := authorizer.AddPrincipal(permission.NewPrincipal("principalA"))

	tenantA.AddPrincipal(principalA.ID(), true, coder.ID())
	tenantA.AssignScopesToPrincipal(principalA.ID(), true, e29.ID())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		V2Test(authorizer)
	}
}

func BenchmarkV1(b *testing.B) {
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

func V2Test(authorizer *permission.RoleManager) {
	authorizer.Authorize("principalA",
		permission.WithTenant("TenantA"),
		permission.WithNamespace("NamespaceA"),
		permission.WithScope("EntityA"),
	)
}

func maincoderPermissions() []*permission.Attribute {
	return []*permission.Attribute{
		permission.NewAttribute("/coding/:wid/:eid/start-coding", "POST"),
		permission.NewAttribute("/coding/:wid/open", "GET"),
		permission.NewAttribute("/coding/:wid/in-progress", "GET"),
		permission.NewAttribute("/coding/:wid/:eid/review", "POST"),
	}
}

func mainqaPermissions() []*permission.Attribute {
	return []*permission.Attribute{
		permission.NewAttribute("/coding/:wid/:eid/start-qa", "POST"),
		permission.NewAttribute("/coding/:wid/qa", "GET"),
		permission.NewAttribute("/coding/:wid/qa-in-progress", "GET"),
		permission.NewAttribute("/coding/:wid/:eid/qa-review", "POST"),
	}
}

func mainsuspendManagerPermissions() []*permission.Attribute {
	return []*permission.Attribute{
		permission.NewAttribute("/coding/:wid/suspended", "GET"),
		permission.NewAttribute("/coding/:wid/:eid/release-suspend", "POST"),
		permission.NewAttribute("/coding/:wid/:eid/request-abandon", "POST"),
	}
}

func mainadminManagerPermissions() []*permission.Attribute {
	return []*permission.Attribute{
		permission.NewAttribute("/admin/principal/add", "POST"),
		permission.NewAttribute("/admin/principal/edit", "PUT"),
	}
}

func mainmyRoles(authorizer *permission.RoleManager) (coder *permission.Role, qa *permission.Role, suspendManager *permission.Role, admin *permission.Role) {
	coder = authorizer.AddRole(permission.NewRole("coder"))
	qa = authorizer.AddRole(permission.NewRole("qa"))
	suspendManager = authorizer.AddRole(permission.NewRole("suspend-manager"))
	admin = authorizer.AddRole(permission.NewRole("admin"))
	err := authorizer.AddPermissionsToRole(coder.ID(), "backend", maincoderPermissions()...)
	if err != nil {
		panic(err)
	}
	err = authorizer.AddPermissionsToRole(qa.ID(), "backend", mainqaPermissions()...)
	if err != nil {
		panic(err)
	}
	err = authorizer.AddPermissionsToRole(suspendManager.ID(), "backend", mainsuspendManagerPermissions()...)
	if err != nil {
		panic(err)
	}
	err = authorizer.AddPermissionsToRole(admin.ID(), "page", mainadminManagerPermissions()...)
	if err != nil {
		panic(err)
	}
	err = admin.AddDescendant(coder, qa, suspendManager)
	if err != nil {
		panic(err)
	}
	return
}

func mainaddAttributes(authorizer *permission.RoleManager) {
	var attrs []*permission.Attribute
	attrs = append(attrs, mainqaPermissions()...)
	attrs = append(attrs, maincoderPermissions()...)
	attrs = append(attrs, mainsuspendManagerPermissions()...)
	backendGroup := permission.NewAttributeGroup("backend")
	backendGroup.AddAttributes(attrs...)
	pageGroup := permission.NewAttributeGroup("page")
	pageGroup.AddAttributes(mainadminManagerPermissions()...)
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
