The package provides functions to handle authorization for a user. An user can be associated with tenant and modules where entities are assigned to a user under multiple roles.

## Use Case
A hospital can have multiple departments. Each department has wards.
An user can be a Director for the hospital but also he could be assigned as Doctor in a department and associated department wards. So this package might be useful to check if the user is allowed to access department, wards in the hospital.


## Example

```go
package main

import (
	"fmt"
	
	"github.com/oarkflow/permission"
)

func main() {
	tenant := permission.NewTenant("TenantA")
	module := permission.NewModule("ModuleA")
	tenant.AddModule(module)
	// tenant.SetDefaultModule(module.ID)
	
	coder, qa, suspendManager, _ := myRoles()
	tenant.AddRole(coder, qa, suspendManager)
	
	e29 := permission.NewEntity("29")
	e30 := permission.NewEntity("30")
	e33 := permission.NewEntity("33")
	
	tenant.AddEntities(e29, e30, e33)
	
	userA := permission.NewUser("userA")
	userB := permission.NewUser("userB")
	userC := permission.NewUser("userC")
	
	tenant.AddUser(userA.ID, coder.ID)
	tenant.AddUser(userB.ID, qa.ID)
	tenant.AddUser(userC.ID, suspendManager.ID)
	
	tenant.AssignEntitiesToUser(userA.ID, e29.ID)
	tenant.AssignEntitiesToUser(userB.ID, e30.ID)
	tenant.AssignEntitiesToUser(userC.ID, e33.ID)
	fmt.Println("R:", permission.Can(userA.ID, "TenantA", "ModuleA", e29.ID, "route", "/coding/1/2/start-coding POST"), "E:", true)
	fmt.Println("R:", permission.Can(userA.ID, "TenantA", "ModuleA", e29.ID, "route", "/coding/1/open GET"), "E:", true)
	fmt.Println("R:", permission.Can(userA.ID, "TenantA", "ModuleA", e29.ID, "backend", "/coding/1/2/start-coding POST"), "E:", false)
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
		{"/admin/user/add", "POST"},
		{"/admin/user/edit", "PUT"},
	}
	admin.AddPermission("route", perm...)
	admin.AddDescendent(coder, qa, suspendManager)
	return
}


```
