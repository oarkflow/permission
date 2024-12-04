package v2

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

func (p Permission) String() string {
	return p.Resource + " " + p.Method
}

type Role struct {
	Name        string
	Permissions map[string]struct{}
	m           sync.RWMutex
}

func NewRole(name string) *Role {
	return &Role{Name: name, Permissions: make(map[string]struct{})}
}

func (r *Role) AddPermission(permissions ...Permission) {
	r.m.Lock()
	defer r.m.Unlock()
	for _, permission := range permissions {
		r.Permissions[permission.String()] = struct{}{}
	}
}

type Scope struct {
	Name      string
	Namespace string
}

type Tenant struct {
	ID           string
	Name         string
	ChildTenants map[string]*Tenant
	Scopes       map[string]Scope
	m            sync.RWMutex
}

func NewTenant(name, id string) *Tenant {
	return &Tenant{ID: id, Name: name, ChildTenants: make(map[string]*Tenant), Scopes: make(map[string]Scope)}
}

func (t *Tenant) AddChildTenant(tenants ...*Tenant) {
	t.m.Lock()
	defer t.m.Unlock()
	for _, tenant := range tenants {
		t.ChildTenants[tenant.ID] = tenant
	}
}

func (t *Tenant) AddScopes(scopes ...Scope) {
	t.m.Lock()
	defer t.m.Unlock()
	for _, scope := range scopes {
		t.Scopes[scope.Name] = scope
	}
}

type UserRole struct {
	UserID   string
	TenantID string
	Scope    string
	Role     string
}

type Request struct {
	UserID   string
	TenantID string
	Scope    string
	Category string
	Resource string
	Method   string
}

type RoleDAG struct {
	mu       sync.RWMutex
	roles    map[string]*Role
	edges    map[string][]string
	resolved map[string]map[string]struct{}
}

func NewRoleDAG() *RoleDAG {
	return &RoleDAG{
		roles:    make(map[string]*Role),
		edges:    make(map[string][]string),
		resolved: make(map[string]map[string]struct{}),
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

func (dag *RoleDAG) ResolvePermissions(roleName string) map[string]struct{} {
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
	result := make(map[string]struct{})
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
		for perm := range role.Permissions {
			result[perm] = struct{}{}
		}
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

func (a *Authorizer) resolveUserRoles(userID, tenantID, scopeName string) (map[string]struct{}, error) {
	tenant, exists := a.tenants[tenantID]
	if !exists {
		return nil, fmt.Errorf("invalid tenant: %v", tenantID)
	}
	scopedPermissions := make(map[string]struct{})
	globalPermissions := make(map[string]struct{})
	for current := tenant; current != nil; current = a.findParentTenant(current) {
		for _, userRole := range a.userRoles {
			if userRole.UserID == userID && userRole.TenantID == current.ID {
				if userRole.Scope == scopeName {
					permissions := a.Roles.ResolvePermissions(userRole.Role)
					for perm := range permissions {
						scopedPermissions[perm] = struct{}{}
					}
				} else if userRole.Scope == "" {
					permissions := a.Roles.ResolvePermissions(userRole.Role)
					for perm := range permissions {
						globalPermissions[perm] = struct{}{}
					}
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
		if _, ok := tenant.ChildTenants[child.ID]; ok {
			return tenant
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
		if request.Scope != "" && !isScopeValid(tenant, request.Scope) {
			continue
		}
		permissions, err := a.resolveUserRoles(request.UserID, tenant.ID, request.Scope)
		if err != nil {
			continue
		}
		for permission := range permissions {
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

func matchPermission(permission string, request Request) bool {
	if request.Resource == "" && request.Method == "" {
		return false
	}
	requestToCheck := request.Resource + " " + request.Method
	return utils.MatchResource(requestToCheck, permission)
}

func isScopeValid(tenant *Tenant, scopeName string) bool {
	if _, ok := tenant.Scopes[scopeName]; ok {
		return true
	}
	for _, child := range tenant.ChildTenants {
		if isScopeValid(child, scopeName) {
			return true
		}
	}
	return false
}
