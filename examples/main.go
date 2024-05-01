package main

import (
	"fmt"

	"github.com/oarkflow/permission"
)

func main() {
	authorizer := permission.New()
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

	fmt.Println("R:", authorizer.Authorize(principalA.ID,
		permission.WithTenant("TenantA"),
		permission.WithNamespace("NamespaceA"),
		permission.WithScope(e29.ID),
		permission.WithResourceGroup("page"),
		permission.WithActivity("/coding/1/2/start-coding POST"),
	), "E:", true)
	fmt.Println("R:", authorizer.Authorize(principalA.ID,
		permission.WithTenant("TenantA"),
		permission.WithNamespace("NamespaceA"),
		permission.WithScope(e29.ID),
		permission.WithResourceGroup("page"),
		permission.WithActivity("/coding/1/open GET"),
	), "E:", true)
	fmt.Println("R:", authorizer.Authorize(principalA.ID,
		permission.WithTenant("TenantA"),
		permission.WithNamespace("NamespaceA"),
		permission.WithScope(e29.ID),
		permission.WithResourceGroup("backend"),
		permission.WithActivity("/coding/1/2/start-coding POST"),
	), "E:", false)
}

func myRoles(authorizer *permission.RoleManager) (coder *permission.Role, qa *permission.Role, suspendManager *permission.Role, admin *permission.Role) {
	coder = authorizer.AddRole(permission.NewRole("coder"))
	perm := []permission.Attribute{
		{"/coding/:wid/:eid/start-coding", "POST"},
		{"/coding/:wid/open", "GET"},
		{"/coding/:wid/in-progress", "GET"},
		{"/coding/:wid/:eid/review", "POST"},
	}
	coder.AddPermission("page", perm...)

	qa = authorizer.AddRole(permission.NewRole("qa"))
	perm = []permission.Attribute{
		{"/coding/:wid/:eid/start-qa", "POST"},
		{"/coding/:wid/qa", "GET"},
		{"/coding/:wid/qa-in-progress", "GET"},
		{"/coding/:wid/:eid/qa-review", "POST"},
	}
	qa.AddPermission("page", perm...)

	suspendManager = authorizer.AddRole(permission.NewRole("suspend-manager"))
	perm = []permission.Attribute{
		{"/coding/:wid/suspended", "GET"},
		{"/coding/:wid/:eid/release-suspend", "POST"},
		{"/coding/:wid/:eid/request-abandon", "POST"},
	}
	suspendManager.AddPermission("page", perm...)

	admin = authorizer.AddRole(permission.NewRole("admin"))
	perm = []permission.Attribute{
		{"/admin/principal/add", "POST"},
		{"/admin/principal/edit", "PUT"},
	}
	admin.AddPermission("page", perm...)
	admin.AddDescendent(coder, qa, suspendManager)
	return
}
