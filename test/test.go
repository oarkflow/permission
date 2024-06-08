package test

import (
	"github.com/oarkflow/permission"
	v2 "github.com/oarkflow/permission"
)

func V2Test(authorizer *v2.RoleManager) {
	authorizer.Authorize("principalA",
		v2.WithTenant("TenantA"),
		v2.WithNamespace("NamespaceA"),
		v2.WithScope("EntityA"),
	)
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

func MainTest(authorizer *permission.RoleManager) {

	authorizer.Authorize("principalA",
		permission.WithTenant("TenantA"),
		permission.WithNamespace("NamespaceA"),
		permission.WithScope("EntityA"),
	)

}

func coderPermissions() []*permission.Attribute {
	return []*permission.Attribute{
		permission.NewAttribute("/coding/:wid/:eid/start-coding", "POST"),
		permission.NewAttribute("/coding/:wid/open", "GET"),
		permission.NewAttribute("/coding/:wid/in-progress", "GET"),
		permission.NewAttribute("/coding/:wid/:eid/review", "POST"),
	}
}

func qaPermissions() []*permission.Attribute {
	return []*permission.Attribute{
		permission.NewAttribute("/coding/:wid/:eid/start-qa", "POST"),
		permission.NewAttribute("/coding/:wid/qa", "GET"),
		permission.NewAttribute("/coding/:wid/qa-in-progress", "GET"),
		permission.NewAttribute("/coding/:wid/:eid/qa-review", "POST"),
	}
}

func suspendManagerPermissions() []*permission.Attribute {
	return []*permission.Attribute{
		permission.NewAttribute("/coding/:wid/suspended", "GET"),
		permission.NewAttribute("/coding/:wid/:eid/release-suspend", "POST"),
		permission.NewAttribute("/coding/:wid/:eid/request-abandon", "POST"),
	}
}

func adminManagerPermissions() []*permission.Attribute {
	return []*permission.Attribute{
		permission.NewAttribute("/admin/principal/add", "POST"),
		permission.NewAttribute("/admin/principal/edit", "PUT"),
	}
}

func myRoles(authorizer *permission.RoleManager) (coder *permission.Role, qa *permission.Role, suspendManager *permission.Role, admin *permission.Role) {
	coder = authorizer.AddRole(permission.NewRole("coder"))
	qa = authorizer.AddRole(permission.NewRole("qa"))
	suspendManager = authorizer.AddRole(permission.NewRole("suspend-manager"))
	admin = authorizer.AddRole(permission.NewRole("admin"))
	err := authorizer.AddPermissionsToRole(coder.ID(), "backend", coderPermissions()...)
	if err != nil {
		panic(err)
	}
	err = authorizer.AddPermissionsToRole(qa.ID(), "backend", qaPermissions()...)
	if err != nil {
		panic(err)
	}
	err = authorizer.AddPermissionsToRole(suspendManager.ID(), "backend", suspendManagerPermissions()...)
	if err != nil {
		panic(err)
	}
	err = authorizer.AddPermissionsToRole(admin.ID(), "page", adminManagerPermissions()...)
	if err != nil {
		panic(err)
	}
	err = admin.AddDescendant(coder, qa, suspendManager)
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
