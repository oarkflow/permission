package main

import (
	"fmt"

	v2 "github.com/oarkflow/permission"
)

func main() {
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
	e29 := authorizer.AddScope(v2.NewScope("Entity29"))
	e30 := authorizer.AddScope(v2.NewScope("Entity30"))
	tenantA.AddScopes(e29)
	tenantB.AddScopes(e30)

	principalA := authorizer.AddPrincipal(v2.NewPrincipal("principalA"))

	tenantA.AddPrincipal(principalA.ID(), true, coder.ID())
	fmt.Println(authorizer.GetImplicitScopesByPrincipal(principalA.ID()))
	// fmt.Println(authorizer.GetScopeRolesByPrincipalTenantAndNamespace())
	fmt.Println("R:", authorizer.Authorize(principalA.ID(),
		v2.WithTenant("TenantA"),
		v2.WithNamespace("NamespaceA"),
		v2.WithScope(e29.ID()),
	), "E:", true)
	fmt.Println("R:", authorizer.Authorize(principalA.ID(),
		v2.WithTenant("TenantA"),
		v2.WithNamespace("NamespaceA"),
		v2.WithScope(e29.ID()),
		v2.WithAttributeGroup("backend"),
		v2.WithActivity("/coding/1/2/start-coding POST"),
	), "E:", true)

	fmt.Println("R:", authorizer.Authorize(principalA.ID(),
		v2.WithTenant("TenantA"),
		v2.WithNamespace("NamespaceA"),
		v2.WithAttributeGroup("backend"),
		v2.WithActivity("/coding/1/2/start-coding POST"),
	), "E:", true)
	fmt.Println("R:", authorizer.Authorize(principalA.ID(),
		v2.WithTenant("TenantB"),
		v2.WithNamespace("NamespaceA"),
		v2.WithScope(e29.ID()),
	), "E:", true)
	fmt.Println("R:", authorizer.Authorize(principalA.ID(),
		v2.WithTenant("TenantB"),
		v2.WithNamespace("NamespaceA"),
		v2.WithScope(e29.ID()),
		v2.WithAttributeGroup("backend"),
		v2.WithActivity("/coding/1/2/start-coding POST"),
	), "E:", true)
	fmt.Println("R:", authorizer.Authorize(principalA.ID(),
		v2.WithTenant("TenantB"),
		v2.WithNamespace("NamespaceA"),
		v2.WithScope(e30.ID()),
		v2.WithAttributeGroup("backend"),
		v2.WithActivity("/coding/1/2/start-coding POST"),
	), "E:", true)
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
