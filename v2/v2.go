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

func (r *Role) RemovePermission(permissions ...Permission) {
	r.m.Lock()
	defer r.m.Unlock()
	for _, permission := range permissions {
		delete(r.Permissions, permission.String())
	}
}

type Scope struct {
	Name string
}

type Namespace struct {
	Name   string
	Scopes map[string]Scope
}

type Tenant struct {
	ID           string
	Name         string
	Namespaces   map[string]Namespace
	DefaultNS    string
	ChildTenants map[string]*Tenant
	m            sync.RWMutex
}

func NewTenant(name, id, defaultNS string) *Tenant {
	return &Tenant{
		ID:           id,
		Name:         name,
		DefaultNS:    defaultNS,
		Namespaces:   map[string]Namespace{defaultNS: {Name: defaultNS, Scopes: make(map[string]Scope)}},
		ChildTenants: make(map[string]*Tenant),
	}
}

func (t *Tenant) AddNamespace(namespace string) {
	t.m.Lock()
	defer t.m.Unlock()
	if _, exists := t.Namespaces[namespace]; !exists {
		t.Namespaces[namespace] = Namespace{Name: namespace, Scopes: make(map[string]Scope)}
	}
}

func (t *Tenant) AddScopeToNamespace(namespace string, scopes ...Scope) error {
	t.m.Lock()
	defer t.m.Unlock()
	ns, exists := t.Namespaces[namespace]
	if !exists {
		return fmt.Errorf("namespace %s does not exist in tenant %s", namespace, t.Name)
	}
	for _, scope := range scopes {
		ns.Scopes[scope.Name] = scope
	}
	t.Namespaces[namespace] = ns
	return nil
}

func (t *Tenant) AddChildTenant(tenants ...*Tenant) {
	t.m.Lock()
	defer t.m.Unlock()
	for _, tenant := range tenants {
		t.ChildTenants[tenant.ID] = tenant
	}
}

type UserRole struct {
	User              string
	Tenant            string
	Scope             string
	Namespace         string
	Role              string
	ManageChildTenant bool
}

type Request struct {
	User      string
	Tenant    string
	Namespace string
	Scope     string
	Resource  string
	Method    string
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

func (dag *RoleDAG) AddChildRole(parent string, child ...string) error {
	dag.mu.Lock()
	defer dag.mu.Unlock()
	if err := dag.checkCircularDependency(parent, child...); err != nil {
		return err
	}
	dag.edges[parent] = append(dag.edges[parent], child...)
	return nil
}

func (dag *RoleDAG) checkCircularDependency(parent string, children ...string) error {
	visited := map[string]bool{parent: true}
	var dfs func(string) bool
	dfs = func(role string) bool {
		if visited[role] {
			return true
		}
		visited[role] = true
		for _, child := range dag.edges[role] {
			if dfs(child) {
				return true
			}
		}
		return false
	}
	for _, child := range children {
		if dfs(child) {
			return fmt.Errorf("circular role dependency detected: %s -> %s", parent, child)
		}
	}
	return nil
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
	roles       *RoleDAG
	userRoles   []UserRole
	tenants     map[string]*Tenant
	parentCache map[string]*Tenant
	m           sync.RWMutex
}

func NewAuthorizer() *Authorizer {
	return &Authorizer{
		roles:       NewRoleDAG(),
		tenants:     make(map[string]*Tenant),
		parentCache: make(map[string]*Tenant),
	}
}

func (a *Authorizer) AddRole(role ...*Role) {
	a.roles.AddRole(role...)
}

func (a *Authorizer) AddChildRole(parent string, child ...string) error {
	return a.roles.AddChildRole(parent, child...)
}

func (a *Authorizer) AddTenant(tenants ...*Tenant) {
	a.m.Lock()
	defer a.m.Unlock()
	for _, tenant := range tenants {
		a.tenants[tenant.ID] = tenant
		for _, child := range tenant.ChildTenants {
			a.parentCache[child.ID] = tenant
		}
	}
}

func (a *Authorizer) AddUserRole(userRole ...UserRole) {
	a.m.Lock()
	defer a.m.Unlock()
	a.userRoles = append(a.userRoles, userRole...)
}

var (
	scopedPermissionsPool = utils.New(func() map[string]struct{} { return make(map[string]struct{}) })
	globalPermissionsPool = utils.New(func() map[string]struct{} { return make(map[string]struct{}) })
	checkedTenantsPool    = utils.New(func() map[string]bool { return make(map[string]bool) })
)

func (a *Authorizer) resolveUserRoles(userID, tenantID, namespace, scopeName string) (map[string]struct{}, error) {
	tenant, exists := a.tenants[tenantID]
	if !exists {
		return nil, fmt.Errorf("invalid tenant: %v", tenantID)
	}
	checkedTenants := make(map[string]bool)
	globalPermissions := globalPermissionsPool.Get()
	scopedPermissions := scopedPermissionsPool.Get()
	clear(scopedPermissions)
	clear(globalPermissions)
	clear(checkedTenants)
	defer func() {
		scopedPermissionsPool.Put(scopedPermissions)
		globalPermissionsPool.Put(globalPermissions)
		checkedTenantsPool.Put(checkedTenants)
	}()
	var traverse func(current *Tenant) error
	traverse = func(current *Tenant) error {
		if checkedTenants[current.ID] {
			return nil
		}
		checkedTenants[current.ID] = true
		for _, userRole := range a.userRoles {
			if userRole.User != userID || userRole.Tenant != current.ID {
				continue
			}
			if userRole.Namespace == "" || userRole.Namespace == namespace {
				permissions := a.roles.ResolvePermissions(userRole.Role)
				if userRole.Scope == scopeName {
					for perm := range permissions {
						scopedPermissions[perm] = struct{}{}
					}
				} else if userRole.Scope == "" {
					for perm := range permissions {
						globalPermissions[perm] = struct{}{}
					}
				}
			}
		}
		for _, userRole := range a.userRoles {
			if userRole.User == userID && userRole.Tenant == current.ID && userRole.ManageChildTenant {
				for _, child := range current.ChildTenants {
					if err := traverse(child); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	if err := traverse(tenant); err != nil {
		return nil, err
	}
	if len(scopedPermissions) > 0 {
		return scopedPermissions, nil
	}
	if len(globalPermissions) > 0 {
		return globalPermissions, nil
	}
	return nil, fmt.Errorf("no roles or permissions found")
}

func (a *Authorizer) isChildTenant(parentID, childID string) bool {
	parent, exists := a.tenants[parentID]
	if !exists {
		return false
	}
	_, exists = parent.ChildTenants[childID]
	return exists
}

func (a *Authorizer) findParentTenant(child *Tenant) *Tenant {
	a.m.RLock()
	defer a.m.RUnlock()
	return a.parentCache[child.ID]
}

func (a *Authorizer) Authorize(request Request) bool {
	var targetTenants []*Tenant
	if request.Tenant == "" {
		targetTenants = a.findUserTenants(request.User)
		if len(targetTenants) == 0 {
			return false
		}
	} else {
		tenant, exists := a.tenants[request.Tenant]
		if !exists {
			return false
		}
		targetTenants = []*Tenant{tenant}
	}
	for _, tenant := range targetTenants {
		namespace := request.Namespace
		if namespace == "" {
			if len(tenant.Namespaces) == 1 {
				namespace = tenant.DefaultNS
			} else {
				return false
			}
		}
		ns, exists := tenant.Namespaces[namespace]
		if !exists {
			continue
		}
		if request.Scope != "" && !a.isScopeValidForNamespace(ns, request.Scope) {
			continue
		}
		permissions, err := a.resolveUserRoles(request.User, tenant.ID, namespace, request.Scope)
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

func (a *Authorizer) isScopeValidForNamespace(ns Namespace, scopeName string) bool {
	_, exists := ns.Scopes[scopeName]
	return exists
}

func (a *Authorizer) findUserTenants(userID string) []*Tenant {
	tenantSet := make(map[string]*Tenant)
	for _, userRole := range a.userRoles {
		if userRole.User == userID {
			if tenant, exists := a.tenants[userRole.Tenant]; exists {
				tenantSet[userRole.Tenant] = tenant
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
