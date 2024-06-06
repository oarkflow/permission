package permission

import (
	"fmt"
	"slices"
	"testing"
)

func IntMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestNewAttribute(t *testing.T) {
	auth := New()
	attr := auth.AddAttribute(NewAttribute("/coding/:wid/:eid/start-coding", "POST"))
	expected := "/coding/:wid/:eid/start-coding POST"
	if attr.String() != expected {
		t.Errorf("Expected %s Actual %s", expected, attr.String())
	}
}

func TestNewRole(t *testing.T) {
	auth := New()
	role := auth.AddRole(NewRole("coder"))
	if role.id != "coder" {
		t.Errorf("Expected %s Actual %s", "coder", role.id)
	}
}

func TestAuthorize(t *testing.T) {
	authorizer := New()
	backendGroup := NewAttributeGroup("backend")
	attr := coderPermissions()
	backendGroup.AddAttributes(attr...)
	authorizer.AddAttributeGroups(backendGroup)
	coder := authorizer.AddRole(NewRole("coder"))
	authorizer.AddPermissionsToRole(coder.ID(), "backend", attr...)

	tenantA := authorizer.AddTenant(NewTenant("TenantA"))
	namespace := authorizer.AddNamespace(NewNamespace("NamespaceA"))
	tenantA.AddNamespace(namespace)
	tenantA.AddRole(coder)

	e29 := authorizer.AddScope(NewScope("29"))
	tenantA.AddScopes(e29)

	principalA := authorizer.AddPrincipal(NewPrincipal("principalA"))
	tenantA.AddPrincipal(principalA.ID(), coder.ID())
	tenantA.AddPrincipalInNamespace(principalA.ID(), namespace.ID())
	tenantA.AssignScopesToPrincipal(principalA.ID(), e29.ID())
	tenantA.AddScopesToNamespace(namespace.id, e29.ID())
	can := authorizer.Authorize(principalA.ID(),
		WithTenant("TenantA"),
		WithNamespace("NamespaceA"),
		WithScope(e29.ID()),
	)
	fmt.Println(can)
}

func TestAllFunctions(t *testing.T) {
	auth := New()
	attr := auth.AddAttribute(NewAttribute("/coding/:wid/:eid/start-coding", "POST"))
	expected := "/coding/:wid/:eid/start-coding POST"
	if attr.String() != expected {
		t.Errorf("Expected %s Actual %s", expected, attr.String())
	}
	coder := auth.AddRole(NewRole("coder"))
	if coder.id != "coder" {
		t.Errorf("Expected %s Actual %s", "coder", coder.id)
	}
	group := auth.AddAttributeGroup(NewAttributeGroup("backend"))
	if group.id != "backend" {
		t.Errorf("Expected %s Actual %s", "backend", group.id)
	}
	group.AddAttributes(attr)
	att, ok := group.permissions.Get(expected)
	if !ok {
		t.Errorf("Expected %s Actual %s", expected, att.String())
	}
	err := auth.AddPermissionsToRole(coder.id, "backend", attr)
	if err != nil {
		t.Errorf("Expected no error Actual %v", err)
	}
	tenantA := auth.AddTenant(NewTenant("TenantA"))
	if tenantA.id != "TenantA" {
		t.Errorf("Expected %s Actual %s", "TenantA", tenantA.id)
	}
	namespace := auth.AddNamespace(NewNamespace("NamespaceA"))
	if namespace.id != "NamespaceA" {
		t.Errorf("Expected %s Actual %s", "NamespaceA", namespace.id)
	}
	tenantA.AddNamespace(namespace)
	nms, ok := tenantA.namespaces.Get("NamespaceA")
	if !ok {
		t.Errorf("Expected %s Actual %s", "NamespaceA", nms.id)
	}
	tenantA.AddRole(coder)
	r, ok := tenantA.roles.Get("coder")
	if !ok {
		t.Errorf("Expected %s Actual %s", "coder", r.id)
	}
	e29 := auth.AddScope(NewScope("29"))
	if e29.ID() != "29" {
		t.Errorf("Expected %s Actual %s", "29", e29.id)
	}
	principalA := auth.AddPrincipal(NewPrincipal("principalA"))
	if principalA.ID() != "principalA" {
		t.Errorf("Expected %s Actual %s", "principalA", principalA.id)
	}
	tenantA.AddPrincipal(principalA.ID(), coder.ID())
	roles := auth.GetPrincipalRoles(tenantA.id, principalA.id)
	foundRole := false
	for _, r := range roles {
		if r.RoleID == coder.ID() {
			foundRole = true
		}
	}
	if !foundRole {
		t.Errorf("Expected %s not found", "coder")
	}
	tenantA.AssignScopesToPrincipal(principalA.ID(), e29.ID())
	scopes, err := auth.GetScopesForPrincipal(principalA.ID())
	if err != nil {
		t.Errorf("Expected no error Actual %v", err)
	}
	if !slices.Contains(scopes, e29.ID()) {
		t.Errorf("Expected %s not found", e29.ID())
	}
	can := auth.Authorize(principalA.ID(),
		WithTenant("TenantA"),
	)
	if !can {
		t.Errorf("Expected true Actual %v", can)
	}
}

func coderPermissions() []*Attribute {
	return []*Attribute{
		NewAttribute("/coding/:wid/:eid/start-coding", "POST"),
		NewAttribute("/coding/:wid/open", "GET"),
		NewAttribute("/coding/:wid/in-progress", "GET"),
		NewAttribute("/coding/:wid/:eid/review", "POST"),
	}
}

func qaPermissions() []*Attribute {
	return []*Attribute{
		NewAttribute("/coding/:wid/:eid/start-qa", "POST"),
		NewAttribute("/coding/:wid/qa", "GET"),
		NewAttribute("/coding/:wid/qa-in-progress", "GET"),
		NewAttribute("/coding/:wid/:eid/qa-review", "POST"),
	}
}

func suspendManagerPermissions() []*Attribute {
	return []*Attribute{
		NewAttribute("/coding/:wid/suspended", "GET"),
		NewAttribute("/coding/:wid/:eid/release-suspend", "POST"),
		NewAttribute("/coding/:wid/:eid/request-abandon", "POST"),
	}
}

func adminManagerPermissions() []*Attribute {
	return []*Attribute{
		NewAttribute("/admin/principal/add", "POST"),
		NewAttribute("/admin/principal/edit", "PUT"),
	}
}
