package main

import (
	"fmt"

	"github.com/oarkflow/permission"
)

func main() {
	authorizer := permission.New()
	addAttributes(authorizer)
	tenant := authorizer.AddTenant(permission.NewTenant("TenantA"))
	namespace := authorizer.AddNamespace(permission.NewNamespace("NamespaceA"))
	tenant.AddNamespace(namespace)
	// tenant.SetDefaultNamespace(namespace.ID)

	coder, qa, suspendManager, _ := myRoles(authorizer)
	tenant.AddRole(coder, qa, suspendManager)
	e29 := authorizer.AddScope(permission.NewScope("29"))
	e30 := authorizer.AddScope(permission.NewScope("30"))
	e33 := authorizer.AddScope(permission.NewScope("33"))
	tenant.AddScopes(e29, e30, e33)

	principalA := authorizer.AddPrincipal(permission.NewPrincipal("principalA"))
	principalB := authorizer.AddPrincipal(permission.NewPrincipal("principalB"))
	principalC := authorizer.AddPrincipal(permission.NewPrincipal("principalC"))

	tenant.AddPrincipal(principalA.ID, coder.ID)
	tenant.AddPrincipal(principalB.ID, qa.ID)
	tenant.AddPrincipal(principalC.ID, suspendManager.ID)

	tenant.AssignScopesToPrincipal(principalA.ID, e29.ID)
	tenant.AssignScopesToPrincipal(principalB.ID, e30.ID)
	tenant.AssignScopesToPrincipal(principalC.ID, e33.ID)

	{
		fmt.Println("R:", authorizer.Authorize(principalA.ID,
			permission.WithTenant("TenantA"),
			permission.WithNamespace("NamespaceA"),
			permission.WithScope(e29.ID),
			permission.WithResourceGroup("backend"),
			permission.WithActivity("/coding/1/2/start-coding POST"),
		), "E:", true)
		fmt.Println("R:", authorizer.Authorize(principalA.ID,
			permission.WithTenant("TenantA"),
			permission.WithNamespace("NamespaceA"),
			permission.WithScope(e29.ID),
			permission.WithResourceGroup("backend"),
			permission.WithActivity("/coding/1/open GET"),
		), "E:", true)
		fmt.Println("R:", authorizer.Authorize(principalA.ID,
			permission.WithTenant("TenantA"),
			permission.WithNamespace("NamespaceA"),
			permission.WithScope(e29.ID),
			permission.WithResourceGroup("backend"),
			permission.WithActivity("/coding/1/2/start-coding POST"),
		), "E:", true)
	}
}

func coderPermissions() []*permission.Attribute {
	return []*permission.Attribute{
		{"/coding/:wid/:eid/start-coding", "POST"},
		{"/coding/:wid/open", "GET"},
		{"/coding/:wid/in-progress", "GET"},
		{"/coding/:wid/:eid/review", "POST"},
	}
}

func qaPermissions() []*permission.Attribute {
	return []*permission.Attribute{
		{"/coding/:wid/:eid/start-qa", "POST"},
		{"/coding/:wid/qa", "GET"},
		{"/coding/:wid/qa-in-progress", "GET"},
		{"/coding/:wid/:eid/qa-review", "POST"},
	}
}

func suspendManagerPermissions() []*permission.Attribute {
	return []*permission.Attribute{
		{"/coding/:wid/suspended", "GET"},
		{"/coding/:wid/:eid/release-suspend", "POST"},
		{"/coding/:wid/:eid/request-abandon", "POST"},
	}
}

func adminManagerPermissions() []*permission.Attribute {
	return []*permission.Attribute{
		{"/admin/principal/add", "POST"},
		{"/admin/principal/edit", "PUT"},
	}
}

func myRoles(authorizer *permission.RoleManager) (coder *permission.Role, qa *permission.Role, suspendManager *permission.Role, admin *permission.Role) {
	coder = authorizer.AddRole(permission.NewRole("coder"))
	qa = authorizer.AddRole(permission.NewRole("qa"))
	suspendManager = authorizer.AddRole(permission.NewRole("suspend-manager"))
	admin = authorizer.AddRole(permission.NewRole("admin"))
	err := authorizer.AddPermissionsToRole(coder.ID, "backend", coderPermissions()...)
	if err != nil {
		panic(err)
	}
	err = authorizer.AddPermissionsToRole(qa.ID, "backend", qaPermissions()...)
	if err != nil {
		panic(err)
	}
	err = authorizer.AddPermissionsToRole(suspendManager.ID, "backend", suspendManagerPermissions()...)
	if err != nil {
		panic(err)
	}
	err = authorizer.AddPermissionsToRole(admin.ID, "page", adminManagerPermissions()...)
	if err != nil {
		panic(err)
	}
	err = admin.AddDescendent(coder, qa, suspendManager)
	if err != nil {
		panic(err)
	}
	return
}

func addAttributes(authorizer *permission.RoleManager) {
	var attrs []*permission.Attribute
	attrs = append(attrs, qaPermissions()...)
	attrs = append(attrs, coderPermissions()...)
	attrs = append(attrs, suspendManagerPermissions()...)
	backendGroup := permission.NewAttributeGroup("backend")
	backendGroup.AddAttributes(attrs...)
	pageGroup := permission.NewAttributeGroup("page")
	pageGroup.AddAttributes(adminManagerPermissions()...)
	authorizer.AddAttributeGroups(backendGroup, pageGroup)
}
