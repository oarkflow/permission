package main

import (
	"fmt"
)

func main() {

	adminRole := Role{
		Name: "Admin",
		Permissions: []Permission{
			{Resource: "dashboard", Method: "read", Category: "page"},
			{Resource: "users", Method: "write", Category: "backend"},
		},
		ChildRoles: []string{"Editor"},
	}
	editorRole := Role{
		Name: "Editor",
		Permissions: []Permission{
			{Resource: "posts", Method: "edit", Category: "backend"},
		},
		ChildRoles: []string{},
	}
	roleMap := map[string]Role{
		"Admin":  adminRole,
		"Editor": editorRole,
	}

	childTenant := &Tenant{
		ID:           "child",
		Name:         "Child Tenant",
		DefaultRole:  "Editor",
		ChildTenants: []*Tenant{},
		Services: []Scope{
			{Name: "scope2", Namespace: "service2"},
		},
	}
	rootTenant := &Tenant{
		ID:           "root",
		Name:         "Root Tenant",
		DefaultRole:  "Admin",
		ChildTenants: []*Tenant{childTenant},
		Services: []Scope{
			{Name: "scope1", Namespace: "service1"},
		},
	}
	tenants := map[string]*Tenant{
		"root":  rootTenant,
		"child": childTenant,
	}

	userRoles := []UserRole{
		{UserID: "user1", TenantID: "root", RoleName: "Admin"},
	}

	request1 := Request{
		UserID:    "user1",
		TenantID:  "root",
		ScopeName: "scope2",
		Category:  "backend",
		Resource:  "users",
		Method:    "write",
	}

	if authorize(request1, userRoles, tenants, roleMap) {
		fmt.Println("Request 1: Access granted")
	} else {
		fmt.Println("Request 1: Access denied")
	}
}

type Permission struct {
	Resource string
	Method   string
	Category string
}

type Role struct {
	Name        string
	Permissions []Permission
	ChildRoles  []string
}

type Scope struct {
	Name      string
	Namespace string
}

type Tenant struct {
	ID           string
	Name         string
	DefaultRole  string
	ChildTenants []*Tenant
	Services     []Scope
}

type UserRole struct {
	UserID    string
	TenantID  string
	ScopeName string
	RoleName  string
}

type Request struct {
	UserID    string
	TenantID  string
	ScopeName string
	Category  string
	Resource  string
	Method    string
}

func isTenantValid(tenantID string, tenants map[string]*Tenant) (*Tenant, bool) {
	tenant, exists := tenants[tenantID]
	return tenant, exists
}

func isRoleValid(roleName string, roleMap map[string]Role) (Role, bool) {
	role, exists := roleMap[roleName]
	return role, exists
}

func isScopeValid(tenant *Tenant, scopeName string) bool {
	for _, scope := range tenant.Services {
		if scope.Name == scopeName {
			return true
		}
	}
	for _, child := range tenant.ChildTenants {
		if isScopeValid(child, scopeName) {
			return true
		}
	}
	return false
}

func expandRoles(roleName string, roleMap map[string]Role, resolvedRoles map[string]bool) {
	if resolvedRoles[roleName] {
		return
	}
	resolvedRoles[roleName] = true
	role, exists := isRoleValid(roleName, roleMap)
	if !exists {
		return
	}
	for _, childRole := range role.ChildRoles {
		expandRoles(childRole, roleMap, resolvedRoles)
	}
}

func resolveUserRoles(userID, tenantID, scopeName string, userRoles []UserRole, tenants map[string]*Tenant, roleMap map[string]Role) ([]Role, error) {
	resolvedRoles := make(map[string]bool)
	tenant, tenantExists := isTenantValid(tenantID, tenants)
	if !tenantExists {
		return nil, fmt.Errorf("invalid tenant: %s", tenantID)
	}
	roleFound := false
	for _, userRole := range userRoles {
		if userRole.UserID == userID && userRole.TenantID == tenantID && userRole.ScopeName == scopeName {
			if role, valid := isRoleValid(userRole.RoleName, roleMap); valid {
				expandRoles(role.Name, roleMap, resolvedRoles)
				roleFound = true
			} else {
				return nil, fmt.Errorf("invalid role: %s", userRole.RoleName)
			}
		}
	}
	if !roleFound {
		if defaultRole, valid := isRoleValid(tenant.DefaultRole, roleMap); valid {
			expandRoles(defaultRole.Name, roleMap, resolvedRoles)
		} else {
			return nil, fmt.Errorf("invalid default role for tenant %s", tenantID)
		}
	}
	var roles []Role
	for roleName := range resolvedRoles {
		if role, exists := isRoleValid(roleName, roleMap); exists {
			roles = append(roles, role)
		}
	}
	return roles, nil
}

func isUserValid(userID string, userRoles []UserRole) bool {
	for _, userRole := range userRoles {
		if userRole.UserID == userID {
			return true
		}
	}
	return false
}

func hasPermission(roles []Role, category, resource, method string) bool {
	for _, role := range roles {
		for _, permission := range role.Permissions {
			if permission.Category == category && permission.Resource == resource && permission.Method == method {
				return true
			}
		}
	}
	return false
}

func authorize(request Request, userRoles []UserRole, tenants map[string]*Tenant, roleMap map[string]Role) bool {
	if !isUserValid(request.UserID, userRoles) {
		fmt.Printf("Invalid user: %s\n", request.UserID)
		return false
	}
	tenant, validTenant := isTenantValid(request.TenantID, tenants)
	if !validTenant {
		fmt.Println("Invalid tenant")
		return false
	}
	if !isScopeValid(tenant, request.ScopeName) {
		fmt.Println("Invalid scope")
		return false
	}
	roles, err := resolveUserRoles(request.UserID, request.TenantID, request.ScopeName, userRoles, tenants, roleMap)
	if err != nil {
		fmt.Println(err)
		return false
	}
	return hasPermission(roles, request.Category, request.Resource, request.Method)
}
