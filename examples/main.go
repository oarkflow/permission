package main

import (
	"fmt"

	"github.com/oarkflow/permission"
)

func main() {
	company := permission.NewCompany("CompanyA")
	module := permission.NewModule("ModuleA")
	company.AddModule(module)
	// company.SetDefaultModule(module.ID)

	coder, qa, suspendManager, _ := myRoles()
	company.AddRole(coder, qa, suspendManager)

	e29 := permission.NewEntity("29")
	e30 := permission.NewEntity("30")
	e33 := permission.NewEntity("33")

	company.AddEntities(e29, e30, e33)

	userA := permission.NewUser("userA")
	userB := permission.NewUser("userB")
	userC := permission.NewUser("userC")

	company.AddUser(userA.ID, coder.ID)
	company.AddUser(userB.ID, qa.ID)
	company.AddUser(userC.ID, suspendManager.ID)

	company.AssignEntitiesToUser(userA.ID, e29.ID)
	company.AssignEntitiesToUser(userB.ID, e30.ID)
	company.AssignEntitiesToUser(userC.ID, e33.ID)
	fmt.Println("R:", permission.Can(userA.ID, "CompanyA", "ModuleA", e29.ID, "page", "/coding/1/2/start-coding POST"), "E:", true)
	fmt.Println("R:", permission.Can(userA.ID, "CompanyA", "ModuleA", e29.ID, "page", "/coding/1/open GET"), "E:", true)
	fmt.Println("R:", permission.Can(userA.ID, "CompanyA", "ModuleA", e29.ID, "backend", "/coding/1/2/start-coding POST"), "E:", false)
}

func myRoles() (coder *permission.Role, qa *permission.Role, suspendManager *permission.Role, admin *permission.Role) {
	coder = permission.NewRole("coder")
	perm := []permission.Attribute{
		{"/coding/:wid/:eid/start-coding", "POST"},
		{"/coding/:wid/open", "GET"},
		{"/coding/:wid/in-progress", "GET"},
		{"/coding/:wid/:eid/review", "POST"},
	}
	coder.AddPermission("page", perm...)

	qa = permission.NewRole("qa")
	perm = []permission.Attribute{
		{"/coding/:wid/:eid/start-qa", "POST"},
		{"/coding/:wid/qa", "GET"},
		{"/coding/:wid/qa-in-progress", "GET"},
		{"/coding/:wid/:eid/qa-review", "POST"},
	}
	qa.AddPermission("page", perm...)

	suspendManager = permission.NewRole("suspend-manager")
	perm = []permission.Attribute{
		{"/coding/:wid/suspended", "GET"},
		{"/coding/:wid/:eid/release-suspend", "POST"},
		{"/coding/:wid/:eid/request-abandon", "POST"},
	}
	suspendManager.AddPermission("page", perm...)

	admin = permission.NewRole("admin")
	perm = []permission.Attribute{
		{"/admin/user/add", "POST"},
		{"/admin/user/edit", "PUT"},
	}
	admin.AddPermission("page", perm...)
	admin.AddDescendent(coder, qa, suspendManager)
	return
}
