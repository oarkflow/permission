package main

import (
	"fmt"
	"sync"

	"github.com/oarkflow/permission/utils"
)

type Permission struct {
	Resource string
	Method   string
	Category string
}

type Role struct {
	Name        string
	Permissions []Permission
	m           sync.RWMutex
}

func NewRole(name string) *Role {
	return &Role{Name: name}
}

func (r *Role) AddPermission(permission ...Permission) {
	r.m.Lock()
	defer r.m.Unlock()
	r.Permissions = append(r.Permissions, permission...)
}

type Scope struct {
	Name      string
	Namespace string
}

type Tenant struct {
	ID           string
	Name         string
	ChildTenants []*Tenant
	Scopes       []Scope
	m            sync.RWMutex
}

func NewTenant(name, id string) *Tenant {
	return &Tenant{ID: id, Name: name}
}

func (t *Tenant) AddChildTenant(tenant ...*Tenant) {
	t.m.Lock()
	defer t.m.Unlock()
	t.ChildTenants = append(t.ChildTenants, tenant...)
}

func (t *Tenant) AddScopes(scope ...Scope) {
	t.m.Lock()
	defer t.m.Unlock()
	t.Scopes = append(t.Scopes, scope...)
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

type RoleDAG struct {
	mu       sync.RWMutex
	roles    map[string]*Role
	edges    map[string][]string
	resolved map[string][]Permission
}

func NewRoleDAG() *RoleDAG {
	return &RoleDAG{
		roles:    make(map[string]*Role),
		edges:    make(map[string][]string),
		resolved: make(map[string][]Permission),
	}
}

func (dag *RoleDAG) AddRole(roles ...*Role) {
	dag.mu.Lock()
	defer dag.mu.Unlock()
	for _, role := range roles {
		dag.roles[role.Name] = role
	}
}

func (dag *RoleDAG) AddChildRole(parent string, child ...string) {
	dag.mu.Lock()
	defer dag.mu.Unlock()
	dag.edges[parent] = append(dag.edges[parent], child...)
}

func (dag *RoleDAG) ResolvePermissions(roleName string) []Permission {
	dag.mu.RLock()
	if permissions, found := dag.resolved[roleName]; found {
		dag.mu.RUnlock()
		return permissions
	}
	dag.mu.RUnlock()
	dag.mu.Lock()
	defer dag.mu.Unlock()
	visited := make(map[string]bool)
	queue := []string{roleName}
	var result []Permission
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if visited[current] {
			continue
		}
		visited[current] = true
		role, exists := dag.roles[current]
		if !exists {
			continue
		}
		result = append(result, role.Permissions...)
		queue = append(queue, dag.edges[current]...)
	}
	dag.resolved[roleName] = result
	return result
}

type Authorizer struct {
	Roles     *RoleDAG
	userRoles []UserRole
	tenants   map[string]*Tenant
	m         sync.RWMutex
}

func NewAuthorizer() *Authorizer {
	return &Authorizer{
		Roles:   NewRoleDAG(),
		tenants: make(map[string]*Tenant),
	}
}

func (a *Authorizer) AddRole(role ...*Role) {
	a.Roles.AddRole(role...)
}

func (a *Authorizer) AddChildRole(parent string, child ...string) {
	a.Roles.AddChildRole(parent, child...)
}

func (a *Authorizer) AddTenant(tenants ...*Tenant) {
	a.m.Lock()
	defer a.m.Unlock()
	for _, tenant := range tenants {
		a.tenants[tenant.ID] = tenant
	}
}

func (a *Authorizer) AddUserRole(userRole ...UserRole) {
	a.m.Lock()
	defer a.m.Unlock()
	a.userRoles = append(a.userRoles, userRole...)
}

func (a *Authorizer) resolveUserRoles(userID, tenantID, scopeName string) ([]Permission, error) {
	tenant, exists := a.tenants[tenantID]
	if !exists {
		return nil, fmt.Errorf("invalid tenant: %v", tenantID)
	}
	var scopedPermissions []Permission
	var globalPermissions []Permission
	for current := tenant; current != nil; current = a.findParentTenant(current) {
		for _, userRole := range a.userRoles {
			if userRole.UserID == userID && userRole.TenantID == current.ID {
				if userRole.ScopeName == scopeName {
					permissions := a.Roles.ResolvePermissions(userRole.RoleName)
					scopedPermissions = append(scopedPermissions, permissions...)
				} else if userRole.ScopeName == "" {
					permissions := a.Roles.ResolvePermissions(userRole.RoleName)
					globalPermissions = append(globalPermissions, permissions...)
				}
			}
		}
	}
	if len(scopedPermissions) > 0 {
		return scopedPermissions, nil
	}
	if len(globalPermissions) > 0 {
		return globalPermissions, nil
	}
	return nil, fmt.Errorf("no roles or permissions found for user: %s in tenant hierarchy of: %s", userID, tenantID)
}

func (a *Authorizer) findParentTenant(child *Tenant) *Tenant {
	for _, tenant := range a.tenants {
		for _, ct := range tenant.ChildTenants {
			if ct.ID == child.ID {
				return tenant
			}
		}
	}
	return nil
}

func (a *Authorizer) Authorize(request Request) bool {
	var targetTenants []*Tenant
	if request.TenantID == "" {
		targetTenants = a.findUserTenants(request.UserID)
		if len(targetTenants) == 0 {
			return false
		}
	} else {
		tenant, exists := a.tenants[request.TenantID]
		if !exists {
			return false
		}
		targetTenants = []*Tenant{tenant}
	}
	for _, tenant := range targetTenants {
		if request.ScopeName != "" && !isScopeValid(tenant, request.ScopeName) {
			continue
		}
		permissions, err := a.resolveUserRoles(request.UserID, tenant.ID, request.ScopeName)
		if err != nil {
			continue
		}
		for _, permission := range permissions {
			if matchPermission(permission, request) {
				return true
			}
		}
	}
	return false
}

func (a *Authorizer) findUserTenants(userID string) []*Tenant {
	tenantSet := make(map[string]*Tenant)
	for _, userRole := range a.userRoles {
		if userRole.UserID == userID {
			if tenant, exists := a.tenants[userRole.TenantID]; exists {
				tenantSet[userRole.TenantID] = tenant
			}
		}
	}
	var tenantList []*Tenant
	for _, tenant := range tenantSet {
		tenantList = append(tenantList, tenant)
	}
	return tenantList
}

func matchPermission(permission Permission, request Request) bool {
	if request.Resource == "" && request.Method == "" {
		return false
	}
	permissionToCheck := permission.Resource + " " + permission.Method
	requestToCheck := request.Resource + " " + request.Method
	return utils.MatchResource(requestToCheck, permissionToCheck)
}

func isScopeValid(tenant *Tenant, scopeName string) bool {
	for _, scope := range tenant.Scopes {
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

func main() {
	authorizer := NewAuthorizer()

	rootTenant := NewTenant("TenantA", "TenantA")
	rootTenant.AddScopes(Scope{Name: "Entity29", Namespace: "NamespaceA"})
	childTenant := NewTenant("TenantB", "TenantB")
	childTenant.AddScopes(Scope{Name: "Entity30", Namespace: "NamespaceA"})
	rootTenant.AddChildTenant(childTenant)

	authorizer.AddTenant(rootTenant, childTenant)
	coder, _, _, _ := myRoles(authorizer)

	authorizer.AddUserRole(UserRole{
		UserID:   "principalA",
		TenantID: rootTenant.ID,
		RoleName: coder.Name,
	})
	r1 := Request{UserID: "principalA", TenantID: rootTenant.ID, ScopeName: "Entity29", Resource: "/coding/1/2/start-coding", Method: "POST"}
	r2 := Request{UserID: "principalA", TenantID: rootTenant.ID, Resource: "/coding/1/2/start-coding", Method: "POST"}
	r3 := Request{UserID: "principalA", TenantID: childTenant.ID, Resource: "/coding/1/2/start-coding", Method: "POST"}
	fmt.Println(authorizer.Authorize(r1))
	fmt.Println(authorizer.Authorize(r2))
	fmt.Println(authorizer.Authorize(r3))
}

func myRoles(authorizer *Authorizer) (coder *Role, qa *Role, suspendManager *Role, admin *Role) {
	coder = NewRole("coder")
	coder.AddPermission(coderPermissions()...)
	authorizer.AddRole(coder)

	qa = NewRole("qa")
	qa.AddPermission(qaPermissions()...)
	authorizer.AddRole(qa)

	suspendManager = NewRole("suspend-manager")
	suspendManager.AddPermission(suspendManagerPermissions()...)
	authorizer.AddRole(suspendManager)

	admin = NewRole("admin")
	admin.AddPermission(adminManagerPermissions()...)
	authorizer.AddRole(admin)

	authorizer.AddChildRole(admin.Name, coder.Name, qa.Name, suspendManager.Name)
	return
}

func coderPermissions() []Permission {
	return []Permission{
		{Resource: "/coding/:wid/:eid/start-coding", Method: "POST", Category: "backend"},
		{Resource: "/coding/:wid/open", Method: "GET", Category: "backend"},
		{Resource: "/coding/:wid/in-progress", Method: "GET", Category: "backend"},
		{Resource: "/coding/:wid/:eid/review", Method: "POST", Category: "backend"},
	}
}

func qaPermissions() []Permission {
	return []Permission{
		{Resource: "/coding/:wid/:eid/start-qa", Method: "POST", Category: "backend"},
		{Resource: "/coding/:wid/qa", Method: "GET", Category: "backend"},
		{Resource: "/coding/:wid/qa-in-progress", Method: "GET", Category: "backend"},
		{Resource: "/coding/:wid/:eid/qa-review", Method: "POST", Category: "backend"},
	}
}

func suspendManagerPermissions() []Permission {
	return []Permission{
		{Resource: "/coding/:wid/suspended", Method: "GET", Category: "backend"},
		{Resource: "/coding/:wid/:eid/release-suspend", Method: "POST", Category: "backend"},
		{Resource: "/coding/:wid/:eid/request-abandon", Method: "POST", Category: "backend"},
	}
}

func adminManagerPermissions() []Permission {
	return []Permission{
		{Resource: "/admin/principal/add", Method: "POST", Category: "backend"},
		{Resource: "/admin/principal/edit", Method: "PUT", Category: "backend"},
	}
}
