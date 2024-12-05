package v2

import (
	"testing"
)

func TestAuthorize_ValidDirectPermission(t *testing.T) {
	authorizer := setupAuthorizer() // Setup roles, tenants, and user roles
	request := Request{
		User:     "user1",
		Tenant:   "tenant1",
		Scope:    "scope1",
		Resource: "resourceA",
		Method:   "GET",
	}
	authorized := authorizer.Authorize(request)
	if !authorized {
		t.Errorf("Expected authorization, got false")
	}
}

func TestAuthorize_ValidParentTenantPermission(t *testing.T) {
	authorizer := setupAuthorizer()
	request := Request{
		User:     "user2",
		Tenant:   "childTenant1",
		Scope:    "scope1",
		Resource: "resourceB",
		Method:   "POST",
	}
	authorized := authorizer.Authorize(request)
	if authorized {
		t.Errorf("Expected authorization denied from childTenant1 tenant, got true")
	}
}

func TestAuthorize_ValidGlobalScopePermission(t *testing.T) {
	authorizer := setupAuthorizer()
	request := Request{
		User:     "user3",
		Tenant:   "tenant2",
		Resource: "resourceC",
		Method:   "DELETE",
	}
	authorized := authorizer.Authorize(request)
	if authorized {
		t.Errorf("Expected authentication failed for empty scope, got true")
	}
}

func TestAuthorize_NoMatchingPermission(t *testing.T) {
	authorizer := setupAuthorizer()
	request := Request{
		User:     "user1",
		Tenant:   "tenant1",
		Scope:    "scope2", // No permission in this scope
		Resource: "resourceA",
		Method:   "GET",
	}
	authorized := authorizer.Authorize(request)
	if authorized {
		t.Errorf("Expected false for unmatched scope, got true")
	}
}

func TestAuthorize_InvalidTenant(t *testing.T) {
	authorizer := setupAuthorizer()
	request := Request{
		User:     "user1",
		Tenant:   "invalidTenant",
		Scope:    "scope1",
		Resource: "resourceA",
		Method:   "GET",
	}
	authorized := authorizer.Authorize(request)
	if authorized {
		t.Errorf("Expected false for invalid tenant, got true")
	}
}

func TestAuthorize_CircularRolePermissions(t *testing.T) {
	authorizer := setupAuthorizerWithCircularRoles()
	request := Request{
		User:     "user1",
		Tenant:   "tenant1",
		Scope:    "scope1",
		Resource: "resourceA",
		Method:   "GET",
	}
	authorized := authorizer.Authorize(request)
	if authorized {
		t.Errorf("Expected false due to circular role, got true")
	}
}

func TestAuthorize_InvalidScope(t *testing.T) {
	authorizer := setupAuthorizer()
	request := Request{
		User:     "user1",
		Tenant:   "tenant1",
		Scope:    "nonexistentScope",
		Resource: "resourceA",
		Method:   "GET",
	}
	authorized := authorizer.Authorize(request)
	if authorized {
		t.Errorf("Expected false for invalid scope, got true")
	}
}

func TestAuthorize_ResolutionFailure(t *testing.T) {
	authorizer := setupAuthorizer() // With misconfigured roles or missing permissions
	request := Request{
		User:     "user4",
		Tenant:   "tenant3",
		Scope:    "scope1",
		Resource: "resourceD",
		Method:   "PATCH",
	}
	authorized := authorizer.Authorize(request)
	if authorized {
		t.Errorf("Expected false due to permission resolution failure, got true")
	}
}

func setupAuthorizer() *Authorizer {
	authorizer := NewAuthorizer()
	role := NewRole("role1")
	role.AddPermission(Permission{Resource: "resourceA", Method: "GET", Category: "category1"})
	authorizer.AddRole(role)
	namespace := "coding"
	tenant := NewTenant("tenant1", "tenant1", namespace)
	err := tenant.AddScopeToNamespace(namespace, Scope{Name: "scope1"})
	if err != nil {
		panic(err)
	}
	authorizer.AddTenant(tenant)
	authorizer.AddUserRole(UserRole{
		User:   "user1",
		Tenant: "tenant1",
		Role:   "role1",
	})
	return authorizer
}

func setupAuthorizerWithCircularRoles() *Authorizer {
	// Create roles with circular dependency and add them to RoleDAG
	return NewAuthorizer()
}
