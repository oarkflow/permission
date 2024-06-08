The package provides functions to handle authorization for a principal. An principal can be associated with tenant and namespaces where scopes are assigned to a principal under multiple roles.

## Use Case
A hospital can have multiple departments. Each department has wards.
An principal can be a Director for the hospital but also he could be assigned as Doctor in a department and associated department wards. So this package might be useful to check if the principal is allowed to access department, wards in the hospital.


## Example

```go
package main

import (
	"fmt"
	
	"github.com/oarkflow/permission"
)

func main() {
	tenant := permission.NewTenant("TenantA")
	namespace := permission.NewNamespace("NamespaceA")
	tenant.AddNamespace(namespace)
	// tenant.SetDefaultNamespace(namespace.ID)
	
	coder, qa, suspendManager, _ := myRoles()
	tenant.AddRole(coder, qa, suspendManager)
	
	e29 := permission.NewScope("29")
	e30 := permission.NewScope("30")
	e33 := permission.NewScope("33")
	
	tenant.AddScopes(e29, e30, e33)
	
	principalA := permission.NewPrincipal("principalA")
	principalB := permission.NewPrincipal("principalB")
	principalC := permission.NewPrincipal("principalC")
	
	tenant.AddPrincipal(principalA.ID, coder.ID)
	tenant.AddPrincipal(principalB.ID, qa.ID)
	tenant.AddPrincipal(principalC.ID, suspendManager.ID)
	
	tenant.AssignScopesToPrincipal(principalA.ID, e29.ID)
	tenant.AssignScopesToPrincipal(principalB.ID, e30.ID)
	tenant.AssignScopesToPrincipal(principalC.ID, e33.ID)
	fmt.Println("R:", permission.Authorize(principalA.ID, "TenantA", "NamespaceA", e29.ID, "route", "/coding/1/2/start-coding POST"), "E:", true)
	fmt.Println("R:", permission.Authorize(principalA.ID, "TenantA", "NamespaceA", e29.ID, "route", "/coding/1/open GET"), "E:", true)
	fmt.Println("R:", permission.Authorize(principalA.ID, "TenantA", "NamespaceA", e29.ID, "backend", "/coding/1/2/start-coding POST"), "E:", false)
}

func myRoles() (coder *permission.Role, qa *permission.Role, suspendManager *permission.Role, admin *permission.Role) {
	coder = permission.NewRole("coder")
	perm := []permission.Attribute{
		{"/coding/:wid/:eid/start-coding", "POST"},
		{"/coding/:wid/open", "GET"},
		{"/coding/:wid/in-progress", "GET"},
		{"/coding/:wid/:eid/review", "POST"},
	}
	coder.AddPermission("route", perm...)
	
	qa = permission.NewRole("qa")
	perm = []permission.Attribute{
		{"/coding/:wid/:eid/start-qa", "POST"},
		{"/coding/:wid/qa", "GET"},
		{"/coding/:wid/qa-in-progress", "GET"},
		{"/coding/:wid/:eid/qa-review", "POST"},
	}
	qa.AddPermission("route", perm...)
	
	suspendManager = permission.NewRole("suspend-manager")
	perm = []permission.Attribute{
		{"/coding/:wid/suspended", "GET"},
		{"/coding/:wid/:eid/release-suspend", "POST"},
		{"/coding/:wid/:eid/request-abandon", "POST"},
	}
	suspendManager.AddPermission("route", perm...)
	
	admin = permission.NewRole("admin")
	perm = []permission.Attribute{
		{"/admin/principal/add", "POST"},
		{"/admin/principal/edit", "PUT"},
	}
	admin.AddPermission("route", perm...)
	admin.AddDescendant(coder, qa, suspendManager)
	return
}


```
