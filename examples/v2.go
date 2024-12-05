package main

import (
	"fmt"

	"github.com/oarkflow/permission/v2"
)

func main() {

	auth := v2.NewAuthorizer()

	adminRole := v2.NewRole("Admin")
	adminRole.AddPermission(
		v2.Permission{Resource: "user", Method: "create"},
		v2.Permission{Resource: "user", Method: "delete"},
	)

	editorRole := v2.NewRole("Editor")
	editorRole.AddPermission(
		v2.Permission{Resource: "post", Method: "edit"},
		v2.Permission{Resource: "post", Method: "publish"},
	)

	auth.AddRole(adminRole, editorRole)

	tenantA := v2.NewTenant("Tenant A", "tenant-a", "default-namespace")
	tenantA.AddNamespace("marketing")
	tenantA.AddNamespace("engineering")

	auth.AddTenant(tenantA)

	tenantA.AddScopeToNamespace("default-namespace", v2.Scope{Name: "default-scope"})
	tenantA.AddScopeToNamespace("marketing", v2.Scope{Name: "campaign-management"})

	auth.AddUserRole(
		v2.UserRole{
			User:      "user1",
			Tenant:    "tenant-a",
			Namespace: "default-namespace",
			Scope:     "default-scope",
			Role:      "Admin",
		},
		v2.UserRole{
			User:      "user2",
			Tenant:    "tenant-a",
			Namespace: "marketing",
			Scope:     "campaign-management",
			Role:      "Editor",
		},
	)

	request1 := v2.Request{
		User:     "user1",
		Tenant:   "tenant-a",
		Category: "default-namespace",
		Scope:    "default-scope",
		Resource: "user",
		Method:   "create",
	}

	request2 := v2.Request{
		User:     "user2",
		Tenant:   "tenant-a",
		Category: "marketing",
		Scope:    "campaign-management",
		Resource: "post",
		Method:   "publish",
	}

	request3 := v2.Request{
		User:     "user2",
		Tenant:   "tenant-a",
		Category: "engineering",
		Scope:    "engineering-scope",
		Resource: "post",
		Method:   "publish",
	}

	fmt.Println("Request 1:", auth.Authorize(request1))
	fmt.Println("Request 2:", auth.Authorize(request2))
	fmt.Println("Request 3:", auth.Authorize(request3))
}
