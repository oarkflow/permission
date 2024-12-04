package main

import (
	"fmt"

	"github.com/oarkflow/permission"
)

func mai1n() {
	authorizer := permission.New()
	v2addAttributes(authorizer)
	tenantA := authorizer.AddTenant(permission.NewTenant("TenantA"))
	tenantB := authorizer.AddTenant(permission.NewTenant("TenantB"))
	namespace := authorizer.AddNamespace(permission.NewNamespace("NamespaceA"))
	tenantA.AddNamespaces(namespace)
	tenantA.AddDescendant(tenantB)
	fmt.Println(authorizer.GetDescendantTenant(tenantA.ID()))
	// tenantA.SetDefaultNamespace(namespace.ID())
	coder, qa, suspendManager, _ := v2myRoles(authorizer)
	tenantA.AddRoles(coder, qa, suspendManager)
	e29 := authorizer.AddScope(permission.NewScope("Entity29"))
	e30 := authorizer.AddScope(permission.NewScope("Entity30"))
	tenantA.AddScopes(e29)
	tenantB.AddScopes(e30)

	principalA := authorizer.AddPrincipal(permission.NewPrincipal("principalA"))
	tenantA.AddScopesToNamespace(namespace.ID(), e29.ID())
	tenantA.AddPrincipal(principalA.ID(), true, coder.ID())
	// fmt.Println(authorizer.GetScopeRolesByPrincipalTenantAndNamespace())
	fmt.Println("R:", authorizer.Authorize(principalA.ID(),
		permission.WithTenant("TenantA"),
		permission.WithNamespace("NamespaceA"),
		permission.WithScope(e29.ID()),
	), "E:", true)
	fmt.Println("R:", authorizer.Authorize(principalA.ID(),
		permission.WithTenant("TenantA"),
		permission.WithNamespace("NamespaceA"),
		permission.WithScope(e29.ID()),
		permission.WithAttributeGroup("backend"),
		permission.WithActivity("/coding/1/2/start-coding POST"),
	), "E:", true)

	fmt.Println("R:", authorizer.Authorize(principalA.ID(),
		permission.WithTenant("TenantA"),
		permission.WithNamespace("NamespaceA"),
		permission.WithAttributeGroup("backend"),
		permission.WithActivity("/coding/1/2/start-coding POST"),
	), "E:", true)
	fmt.Println("R:", authorizer.Authorize(principalA.ID(),
		permission.WithTenant("TenantB"),
		permission.WithNamespace("NamespaceA"),
		permission.WithScope(e29.ID()),
	), "E:", true)
	fmt.Println("R:", authorizer.Authorize(principalA.ID(),
		permission.WithTenant("TenantB"),
		permission.WithNamespace("NamespaceA"),
		permission.WithScope(e29.ID()),
		permission.WithAttributeGroup("backend"),
		permission.WithActivity("/coding/1/2/start-coding POST"),
	), "E:", true)
	fmt.Println("R:", authorizer.Authorize(principalA.ID(),
		permission.WithTenant("TenantB"),
		permission.WithNamespace("NamespaceA"),
		permission.WithScope(e30.ID()),
		permission.WithAttributeGroup("backend"),
		permission.WithActivity("/coding/1/2/start-coding POST"),
	), "E:", true)
}

func v2coderPermissions() []*permission.Attribute {
	return []*permission.Attribute{
		permission.NewAttribute("/coding/:wid/:eid/start-coding", "POST"),
		permission.NewAttribute("/coding/:wid/open", "GET"),
		permission.NewAttribute("/coding/:wid/in-progress", "GET"),
		permission.NewAttribute("/coding/:wid/:eid/review", "POST"),
	}
}

func v2qaPermissions() []*permission.Attribute {
	return []*permission.Attribute{
		permission.NewAttribute("/coding/:wid/:eid/start-qa", "POST"),
		permission.NewAttribute("/coding/:wid/qa", "GET"),
		permission.NewAttribute("/coding/:wid/qa-in-progress", "GET"),
		permission.NewAttribute("/coding/:wid/:eid/qa-review", "POST"),
	}
}

func v2suspendManagerPermissions() []*permission.Attribute {
	return []*permission.Attribute{
		permission.NewAttribute("/coding/:wid/suspended", "GET"),
		permission.NewAttribute("/coding/:wid/:eid/release-suspend", "POST"),
		permission.NewAttribute("/coding/:wid/:eid/request-abandon", "POST"),
	}
}

func v2adminManagerPermissions() []*permission.Attribute {
	return []*permission.Attribute{
		permission.NewAttribute("/admin/principal/add", "POST"),
		permission.NewAttribute("/admin/principal/edit", "PUT"),
	}
}

func v2myRoles(authorizer *permission.RoleManager) (coder *permission.Role, qa *permission.Role, suspendManager *permission.Role, admin *permission.Role) {
	coder = authorizer.AddRole(permission.NewRole("coder"))
	qa = authorizer.AddRole(permission.NewRole("qa"))
	suspendManager = authorizer.AddRole(permission.NewRole("suspend-manager"))
	admin = authorizer.AddRole(permission.NewRole("admin"))
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

func v2addAttributes(authorizer *permission.RoleManager) {
	var attrs []*permission.Attribute
	attrs = append(attrs, v2qaPermissions()...)
	attrs = append(attrs, v2coderPermissions()...)
	attrs = append(attrs, v2suspendManagerPermissions()...)
	backendGroup := permission.NewAttributeGroup("backend")
	backendGroup.AddAttributes(attrs...)
	pageGroup := permission.NewAttributeGroup("page")
	pageGroup.AddAttributes(v2adminManagerPermissions()...)
	authorizer.AddAttributeGroups(backendGroup, pageGroup)
}
