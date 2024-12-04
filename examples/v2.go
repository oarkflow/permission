package main

import (
	"fmt"

	v2 "github.com/oarkflow/permission/v2"
)

func main() {
	authorizer := v2.NewAuthorizer()

	rootTenant := v2.NewTenant("TenantA", "TenantA")
	rootTenant.AddScopes(v2.Scope{Name: "Entity29", Namespace: "NamespaceA"})
	childTenant := v2.NewTenant("TenantB", "TenantB")
	childTenant.AddScopes(v2.Scope{Name: "Entity30", Namespace: "NamespaceA"})
	rootTenant.AddChildTenant(childTenant)

	authorizer.AddTenant(rootTenant, childTenant)
	coder, _, _, _ := myRoles(authorizer)

	authorizer.AddUserRole(v2.UserRole{
		UserID:   "principalA",
		TenantID: rootTenant.ID,
		Role:     coder.Name,
	})
	r1 := v2.Request{UserID: "principalA", TenantID: rootTenant.ID, Scope: "Entity29", Resource: "/coding/1/2/start-coding", Method: "POST"}
	r2 := v2.Request{UserID: "principalA", TenantID: rootTenant.ID, Resource: "/coding/1/2/start-coding", Method: "POST"}
	r3 := v2.Request{UserID: "principalA", TenantID: childTenant.ID, Resource: "/coding/1/2/start-coding", Method: "POST"}
	fmt.Println(authorizer.Authorize(r1))
	fmt.Println(authorizer.Authorize(r2))
	fmt.Println(authorizer.Authorize(r3))
}

func myRoles(authorizer *v2.Authorizer) (coder *v2.Role, qa *v2.Role, suspendManager *v2.Role, admin *v2.Role) {
	coder = v2.NewRole("coder")
	coder.AddPermission(coderPermissions()...)
	authorizer.AddRole(coder)

	qa = v2.NewRole("qa")
	qa.AddPermission(qaPermissions()...)
	authorizer.AddRole(qa)

	suspendManager = v2.NewRole("suspend-manager")
	suspendManager.AddPermission(suspendManagerPermissions()...)
	authorizer.AddRole(suspendManager)

	admin = v2.NewRole("admin")
	admin.AddPermission(adminManagerPermissions()...)
	authorizer.AddRole(admin)

	err := authorizer.AddChildRole(admin.Name, coder.Name, qa.Name, suspendManager.Name)
	if err != nil {
		panic(err)
	}
	return
}

func coderPermissions() []v2.Permission {
	return []v2.Permission{
		{Resource: "/coding/:wid/:eid/start-coding", Method: "POST", Category: "backend"},
		{Resource: "/coding/:wid/open", Method: "GET", Category: "backend"},
		{Resource: "/coding/:wid/in-progress", Method: "GET", Category: "backend"},
		{Resource: "/coding/:wid/:eid/review", Method: "POST", Category: "backend"},
	}
}

func qaPermissions() []v2.Permission {
	return []v2.Permission{
		{Resource: "/coding/:wid/:eid/start-qa", Method: "POST", Category: "backend"},
		{Resource: "/coding/:wid/qa", Method: "GET", Category: "backend"},
		{Resource: "/coding/:wid/qa-in-progress", Method: "GET", Category: "backend"},
		{Resource: "/coding/:wid/:eid/qa-review", Method: "POST", Category: "backend"},
	}
}

func suspendManagerPermissions() []v2.Permission {
	return []v2.Permission{
		{Resource: "/coding/:wid/suspended", Method: "GET", Category: "backend"},
		{Resource: "/coding/:wid/:eid/release-suspend", Method: "POST", Category: "backend"},
		{Resource: "/coding/:wid/:eid/request-abandon", Method: "POST", Category: "backend"},
	}
}

func adminManagerPermissions() []v2.Permission {
	return []v2.Permission{
		{Resource: "/admin/principal/add", Method: "POST", Category: "backend"},
		{Resource: "/admin/principal/edit", Method: "PUT", Category: "backend"},
	}
}
