package v2

import (
	"fmt"
	"sync"

	"github.com/oarkflow/permission/utils"
)

func (p *Permission) String() string {
	return p.Resource + " " + p.Action
}

func (r *Role) AddPermission(permissions ...*Permission) {
	r.m.Lock()
	defer r.m.Unlock()
	for _, permission := range permissions {
		r.Permissions[permission.String()] = struct{}{}
	}
}

func (r *Role) RemovePermission(permissions ...*Permission) {
	r.m.Lock()
	defer r.m.Unlock()
	for _, permission := range permissions {
		delete(r.Permissions, permission.String())
	}
}

func (t *Tenant) AddNamespace(namespace string, isDefault ...bool) {
	t.m.Lock()
	defer t.m.Unlock()
	if _, exists := t.Namespaces[namespace]; !exists {
		t.Namespaces[namespace] = NewNamespace(namespace)
	}
	if len(isDefault) > 0 && isDefault[0] {
		t.DefaultNS = namespace
	}
}

func (t *Tenant) AddScopeToNamespace(namespace string, scopes ...*Scope) error {
	t.m.Lock()
	defer t.m.Unlock()
	ns, exists := t.Namespaces[namespace]
	if !exists {
		return fmt.Errorf("namespace %s does not exist in tenant %s", namespace, t.ID)
	}
	for _, scope := range scopes {
		ns.Scopes[scope.ID] = scope
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

type PrincipalRole struct {
	Principal         string
	Tenant            string
	Scope             string
	Namespace         string
	Role              string
	ManageChildTenant bool
}

type Request struct {
	Principal string
	Tenant    string
	Namespace string
	Scope     string
	Resource  string
	Action    string
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
	roleDAG     *RoleDAG
	userRoles   []PrincipalRole
	userRoleMap map[string]map[string][]PrincipalRole // Map[userID][tenantID][]PrincipalRole
	tenants     map[string]*Tenant
	namespaces  map[string]*Namespace
	scopes      map[string]*Scope
	principals  map[string]*Principal
	permissions map[string]*Permission
	parentCache map[string]*Tenant
	m           sync.RWMutex
}

func NewAuthorizer() *Authorizer {
	return &Authorizer{
		roleDAG:     NewRoleDAG(),
		tenants:     make(map[string]*Tenant),
		parentCache: make(map[string]*Tenant),
		namespaces:  make(map[string]*Namespace),
		scopes:      make(map[string]*Scope),
		principals:  make(map[string]*Principal),
		userRoleMap: make(map[string]map[string][]PrincipalRole),
	}
}

func (a *Authorizer) AddRoles(role ...*Role) {
	a.roleDAG.AddRole(role...)
}

func (a *Authorizer) AddRole(role *Role) *Role {
	a.AddRoles(role)
	return role
}

func (a *Authorizer) GetRole(val string) (*Role, bool) {
	role, ok := a.roleDAG.roles[val]
	return role, ok
}

func (a *Authorizer) AddPrincipals(p ...*Principal) {
	for _, principal := range p {
		a.AddPrincipal(principal)
	}
}

func (a *Authorizer) AddPrincipal(p *Principal) *Principal {
	a.m.Lock()
	defer a.m.Unlock()
	a.principals[p.ID] = p
	return p
}

func (a *Authorizer) GetPrincipal(val string) (*Principal, bool) {
	data, ok := a.principals[val]
	return data, ok
}

func (a *Authorizer) AddNamespaces(p ...*Namespace) {
	for _, namespace := range p {
		a.AddNamespace(namespace)
	}
}

func (a *Authorizer) AddNamespace(p *Namespace) *Namespace {
	a.m.Lock()
	defer a.m.Unlock()
	a.namespaces[p.ID] = p
	return p
}

func (a *Authorizer) GetNamespace(val string) (*Namespace, bool) {
	data, ok := a.namespaces[val]
	return data, ok
}

func (a *Authorizer) AddScopes(p ...*Scope) {
	for _, namespace := range p {
		a.AddScope(namespace)
	}
}

func (a *Authorizer) AddScope(p *Scope) *Scope {
	a.m.Lock()
	defer a.m.Unlock()
	a.scopes[p.ID] = p
	return p
}

func (a *Authorizer) GetScope(val string) (*Scope, bool) {
	data, ok := a.scopes[val]
	return data, ok
}

func (a *Authorizer) AddPermissions(p ...*Permission) {
	for _, namespace := range p {
		a.AddPermission(namespace)
	}
}

func (a *Authorizer) AddPermission(p *Permission) *Permission {
	a.m.Lock()
	defer a.m.Unlock()
	a.permissions[p.String()] = p
	return p
}

func (a *Authorizer) GetPermission(val string) (*Permission, bool) {
	data, ok := a.permissions[val]
	return data, ok
}

func (a *Authorizer) AddChildRole(parent string, child ...string) error {
	return a.roleDAG.AddChildRole(parent, child...)
}

func (a *Authorizer) AddTenants(tenants ...*Tenant) {
	for _, tenant := range tenants {
		a.AddTenant(tenant)
	}
}

func (a *Authorizer) AddTenant(tenant *Tenant) *Tenant {
	a.m.Lock()
	defer a.m.Unlock()
	a.tenants[tenant.ID] = tenant
	for _, child := range tenant.ChildTenants {
		a.parentCache[child.ID] = tenant
	}
	return tenant
}

func (a *Authorizer) GetTenant(id string) (*Tenant, bool) {
	a.m.Lock()
	defer a.m.Unlock()
	tenant, ok := a.tenants[id]
	return tenant, ok
}

func (a *Authorizer) AddPrincipalRole(userRole ...PrincipalRole) {
	a.m.Lock()
	defer a.m.Unlock()
	for _, ur := range userRole {
		a.userRoles = append(a.userRoles, ur)
		if a.userRoleMap[ur.Principal] == nil {
			a.userRoleMap[ur.Principal] = make(map[string][]PrincipalRole)
		}
		a.userRoleMap[ur.Principal][ur.Tenant] = append(a.userRoleMap[ur.Principal][ur.Tenant], ur)
	}
}

var (
	scopedPermissionsPool = utils.New(func() map[string]struct{} { return make(map[string]struct{}) })
	globalPermissionsPool = utils.New(func() map[string]struct{} { return make(map[string]struct{}) })
	checkedTenantsPool    = utils.New(func() map[string]bool { return make(map[string]bool) })
)

func (a *Authorizer) resolvePrincipalRoles(userID, tenantID, namespace, scopeName string) (map[string]struct{}, error) {
	tenant, exists := a.tenants[tenantID]
	if !exists {
		return nil, fmt.Errorf("invalid tenant: %v", tenantID)
	}
	globalPermissions := globalPermissionsPool.Get()
	scopedPermissions := scopedPermissionsPool.Get()
	checkedTenants := checkedTenantsPool.Get()
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
			if userRole.Principal != userID || userRole.Tenant != current.ID {
				continue
			}
			if userRole.Namespace == "" || userRole.Namespace == namespace {
				permissions := a.roleDAG.ResolvePermissions(userRole.Role)
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
			if userRole.Principal == userID && userRole.Tenant == current.ID && userRole.ManageChildTenant {
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
	return nil, fmt.Errorf("no roleDAG or permissions found")
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

var tenantPool = utils.NewSlicePool[*Tenant](10)

func (a *Authorizer) Authorize(request Request) bool {
	targetTenants := tenantPool.Get()
	clear(targetTenants)
	defer func() {
		tenantPool.Put(targetTenants)
	}()
	if request.Tenant == "" {
		targetTenants = a.findPrincipalTenants(request.Principal)
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
			if tenant.DefaultNS != "" {
				namespace = tenant.DefaultNS
			} else if len(tenant.Namespaces) == 1 {
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
		permissions, err := a.resolvePrincipalRoles(request.Principal, tenant.ID, namespace, request.Scope)
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

func (a *Authorizer) isScopeValidForNamespace(ns *Namespace, scopeName string) bool {
	_, exists := ns.Scopes[scopeName]
	return exists
}

func (a *Authorizer) findPrincipalTenants(userID string) []*Tenant {
	tenantSet := make(map[string]*Tenant)
	for _, userRole := range a.userRoles {
		if userRole.Principal == userID {
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
	if request.Resource == "" && request.Action == "" {
		return false
	}
	requestToCheck := request.Resource + " " + request.Action
	return utils.MatchResource(requestToCheck, permission)
}
