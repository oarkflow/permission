package main

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/oarkflow/permission/v2"
)

func main() {
	auth := v2.NewAuthorizer(slog.New(slog.NewJSONHandler(os.Stderr, nil)))

	adminRole := v2.NewRole("Admin")
	adminRole.AddPermission(
		v2.NewPermission("backend", "user/:id", "create"),
		v2.NewPermission("backend", "user", "delete"),
	)

	editorRole := v2.NewRole("Editor")
	editorRole.AddPermission(
		v2.NewPermission("backend", "post", "edit"),
		v2.NewPermission("backend", "post", "publish"),
	)

	auth.AddRoles(adminRole, editorRole)

	tenantA := v2.NewTenant("tenant-a", "default-namespace")
	tenantA.AddNamespace("marketing")
	tenantA.AddNamespace("engineering")
	auth.AddTenant(tenantA)

	err := tenantA.AddScopeToNamespace("default-namespace", v2.NewScope("default-scope"))
	if err != nil {
		panic(err)
	}
	err = tenantA.AddScopeToNamespace("marketing", v2.NewScope("campaign-management"))
	if err != nil {
		panic(err)
	}
	userRole := &v2.PrincipalRole{
		Principal:         "user1",
		Tenant:            "tenant-a",
		Role:              "Admin",
		ManageChildTenant: true,
	}
	err = userRole.SetExpiryDuration("5s")
	if err != nil {
		panic(err)
	}
	auth.AddPrincipalRole(
		userRole,
		&v2.PrincipalRole{
			Principal: "user2",
			Tenant:    "tenant-a",
			Namespace: "marketing",
			Scope:     "campaign-management",
			Role:      "Editor",
		},
	)

	request1 := v2.Request{
		Principal: "user1",
		Tenant:    "tenant-a",
		Scope:     "default-scope",
		Resource:  "user/1",
		Action:    "create",
	}

	request2 := v2.Request{
		Principal: "user2",
		Tenant:    "tenant-a",
		Namespace: "marketing",
		Scope:     "campaign-management",
		Resource:  "post",
		Action:    "publish",
	}

	request3 := v2.Request{
		Principal: "user2",
		Tenant:    "tenant-a",
		Namespace: "engineering",
		Scope:     "engineering-scope",
		Resource:  "post",
		Action:    "publish",
	}

	fmt.Println("Request 1:", auth.Authorize(request1))
	fmt.Println("Request 2:", auth.Authorize(request2))
	fmt.Println("Request 3:", auth.Authorize(request3))
	time.Sleep(5 * time.Second)
	fmt.Println("Request 1:", auth.Authorize(request1))
}
