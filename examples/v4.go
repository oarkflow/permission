package main

import (
	"fmt"
)

func main() {
	// Initialize roles
	adminRole := Role{
		Name: "Admin",
		Permissions: []Permission{
			{Resource: "dashboard", Method: "read", Category: "page"},
			{Resource: "users", Method: "write", Category: "backend"},
		},
	}
	editorRole := Role{
		Name: "Editor",
		Permissions: []Permission{
			{Resource: "posts", Method: "edit", Category: "backend"},
		},
	}
	// Define role relationships in DAG
	roleDAG := NewRoleDAG()
	roleDAG.AddRole(adminRole)
	roleDAG.AddRole(editorRole)
	roleDAG.AddChildRole("Admin", "Editor")

	// Initialize tenants
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

	// User roles
	userRoles := []UserRole{
		{UserID: "user1", TenantID: "root", RoleName: "Admin"},
	}

	// Example request
	request := Request{
		UserID:    "user1",
		TenantID:  "root",
		ScopeName: "scope1",
		Category:  "backend",
		Resource:  "users",
		Method:    "write",
	}

	// Authorize request
	if authorize(request, userRoles, tenants, roleDAG) {
		fmt.Println("Request: Access granted")
	} else {
		fmt.Println("Request: Access denied")
	}
}

// Permission, Role, and Scope definitions
type Permission struct {
	Resource string
	Method   string
	Category string
}

type Role struct {
	Name        string
	Permissions []Permission
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
	UserID   string
	TenantID string
	RoleName string
}

type Request struct {
	UserID    string
	TenantID  string
	ScopeName string
	Category  string
	Resource  string
	Method    string
}

// Role DAG implementation
type RoleDAG struct {
	roles    map[string]Role
	edges    map[string][]string
	resolved map[string][]Permission
}

func NewRoleDAG() *RoleDAG {
	return &RoleDAG{
		roles:    make(map[string]Role),
		edges:    make(map[string][]string),
		resolved: make(map[string][]Permission),
	}
}

func (dag *RoleDAG) AddRole(role Role) {
	dag.roles[role.Name] = role
}

func (dag *RoleDAG) AddChildRole(parent, child string) {
	dag.edges[parent] = append(dag.edges[parent], child)
}

func (dag *RoleDAG) ResolvePermissions(roleName string) []Permission {
	if permissions, found := dag.resolved[roleName]; found {
		return permissions
	}
	visited := make(map[string]bool)
	var result []Permission
	dag.dfs(roleName, visited, &result)
	dag.resolved[roleName] = result
	return result
}

func (dag *RoleDAG) dfs(roleName string, visited map[string]bool, permissions *[]Permission) {
	if visited[roleName] {
		return
	}
	visited[roleName] = true
	role, exists := dag.roles[roleName]
	if !exists {
		return
	}
	*permissions = append(*permissions, role.Permissions...)
	for _, child := range dag.edges[roleName] {
		dag.dfs(child, visited, permissions)
	}
}

// Authorization functions
func resolveUserRoles(userID, tenantID string, userRoles []UserRole, tenants map[string]*Tenant, dag *RoleDAG) ([]Permission, error) {
	tenant, ok := tenants[tenantID]
	if !ok {
		return nil, fmt.Errorf("invalid tenant: %s", tenantID)
	}
	for _, userRole := range userRoles {
		if userRole.UserID == userID && userRole.TenantID == tenantID {
			return dag.ResolvePermissions(userRole.RoleName), nil
		}
	}
	return dag.ResolvePermissions(tenant.DefaultRole), nil
}

func authorize(request Request, userRoles []UserRole, tenants map[string]*Tenant, dag *RoleDAG) bool {
	tenant, exists := tenants[request.TenantID]
	if !exists {
		fmt.Printf("Invalid tenant: %s\n", request.TenantID)
		return false
	}
	if !isScopeValid(tenant, request.ScopeName) {
		fmt.Printf("Invalid scope: %s\n", request.ScopeName)
		return false
	}
	permissions, err := resolveUserRoles(request.UserID, request.TenantID, userRoles, tenants, dag)
	if err != nil {
		fmt.Println(err)
		return false
	}
	for _, permission := range permissions {
		if permission.Category == request.Category && permission.Resource == request.Resource && permission.Method == request.Method {
			return true
		}
	}
	return false
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
