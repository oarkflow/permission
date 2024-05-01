package permission

import (
	"slices"

	"github.com/oarkflow/maps"
)

var roleManager *RoleManager

func init() {
	roleManager = New()
}

// Principal represents a principal with a role
type Principal struct {
	ID      string
	manager *RoleManager
}

// Can check if a principal is allowed to do an activity based on their role and inherited permissions
func (u *Principal) Can(options ...func(*Option)) bool {
	return Can(u.ID, options...)
}

type PrincipalRole struct {
	PrincipalID          string
	RoleID               string
	CanManageDescendants bool
	Tenant               *Tenant
	Namespace            *Namespace
	Scope                *Scope
}

type TenantPrincipal struct {
	Tenant               *Tenant
	Principal            *Principal
	CanManageDescendants bool
	Roles                []*PrincipalRole
}

type RoleManager struct {
	tenants          maps.IMap[string, *Tenant]
	namespaces       maps.IMap[string, *Namespace]
	scopes           maps.IMap[string, *Scope]
	principals       maps.IMap[string, *Principal]
	roles            maps.IMap[string, *Role]
	tenantPrincipals maps.IMap[string, *TenantPrincipal]
}

func New() *RoleManager {
	return &RoleManager{
		tenants:          maps.New[string, *Tenant](),
		namespaces:       maps.New[string, *Namespace](),
		scopes:           maps.New[string, *Scope](),
		principals:       maps.New[string, *Principal](),
		roles:            maps.New[string, *Role](),
		tenantPrincipals: maps.New[string, *TenantPrincipal](),
	}
}

func (u *RoleManager) AddRole(role *Role) {
	u.roles.Set(role.ID, role)
}

func (u *RoleManager) GetRole(role string) (*Role, bool) {
	return u.roles.Get(role)
}

func (u *RoleManager) Roles() map[string]*Role {
	return u.roles.AsMap()
}

func (u *RoleManager) AddTenant(data *Tenant) {
	u.tenants.Set(data.ID, data)
}

func (u *RoleManager) GetTenant(id string) (*Tenant, bool) {
	return u.tenants.Get(id)
}

func (u *RoleManager) Tenants() map[string]*Tenant {
	return u.tenants.AsMap()
}

func (u *RoleManager) AddNamespace(data *Namespace) {
	u.namespaces.Set(data.ID, data)
}

func (u *RoleManager) GetNamespace(id string) (*Namespace, bool) {
	return u.namespaces.Get(id)
}

func (u *RoleManager) Namespaces() map[string]*Namespace {
	return u.namespaces.AsMap()
}

func (u *RoleManager) AddPrincipal(data *Principal) {
	u.principals.Set(data.ID, data)
}

func (u *RoleManager) GetPrincipal(id string) (*Principal, bool) {
	return u.principals.Get(id)
}

func (u *RoleManager) Principals() map[string]*Principal {
	return u.principals.AsMap()
}

func (u *RoleManager) AddScope(data *Scope) {
	u.scopes.Set(data.ID, data)
}

func (u *RoleManager) GetScope(id string) (*Scope, bool) {
	return u.scopes.Get(id)
}

func (u *RoleManager) Scopes() map[string]*Scope {
	return u.scopes.AsMap()
}

func (u *RoleManager) AddPrincipalRole(principalID string, roleID string, tenant *Tenant, namespace *Namespace, scope *Scope, canManageDescendants ...bool) {
	manageDescendants := true
	if len(canManageDescendants) > 0 {
		manageDescendants = canManageDescendants[0]
	}
	role := &PrincipalRole{
		PrincipalID:          principalID,
		RoleID:               roleID,
		Tenant:               tenant,
		Namespace:            namespace,
		Scope:                scope,
		CanManageDescendants: manageDescendants,
	}
	tenantPrincipal, ok := u.tenantPrincipals.Get(tenant.ID)
	if !ok {
		tenantPrincipal = &TenantPrincipal{
			Tenant:               tenant,
			Principal:            &Principal{ID: principalID},
			CanManageDescendants: manageDescendants,
		}
	}
	tenantPrincipal.Roles = append(tenantPrincipal.Roles, role)
	u.tenantPrincipals.Set(tenant.ID, tenantPrincipal)
}

func (u *RoleManager) GetTenantPrincipalRoles(tenant string) *TenantPrincipal {
	principalRoles, ok := u.tenantPrincipals.Get(tenant)
	if !ok {
		return nil
	}
	return principalRoles
}

func (u *RoleManager) GetPrincipalRoles(tenant, principalID string) *TenantPrincipal {
	principalRoles, ok := u.tenantPrincipals.Get(tenant)
	if !ok {
		return nil
	}
	roles := make([]*PrincipalRole, 0, len(principalRoles.Roles))
	principalFound := false
	for _, ut := range principalRoles.Roles {
		if ut.PrincipalID == principalID {
			principalFound = true
			roles = append(roles, ut)
		}
	}
	if !principalFound {
		return nil
	}
	return &TenantPrincipal{
		Tenant:               principalRoles.Tenant,
		Principal:            principalRoles.Principal,
		CanManageDescendants: principalRoles.CanManageDescendants,
		Roles:                roles,
	}
}

func (u *RoleManager) GetPrincipalRolesByTenant(tenant string) []*PrincipalRole {
	principalRoles, ok := u.tenantPrincipals.Get(tenant)
	if !ok {
		return nil
	}
	return principalRoles.Roles
}

func (u *RoleManager) GetPrincipalRoleByTenantAndPrincipal(tenant, principalID string) (ut []*PrincipalRole) {
	principalRoles, ok := u.tenantPrincipals.Get(tenant)
	if !ok {
		return
	}
	for _, ur := range principalRoles.Roles {
		if ur.PrincipalID == principalID {
			ut = append(ut, ur)
		}
	}
	return
}

func (u *RoleManager) GetAllowedRoles(principalRoles *TenantPrincipal, namespace, scope string) []string {
	if principalRoles == nil {
		return nil
	}
	// Reusable slices
	namespaceScopes := stringSlice.Get()
	namespaceRoles := stringSlice.Get()
	scopes := stringSlice.Get()
	allowedRoles := stringSlice.Get()
	principalTenantRole := principalRoleSlice.Get()
	principalNamespaceScopeRole := principalRoleSlice.Get()
	defer func() {
		stringSlice.Put(namespaceScopes)
		stringSlice.Put(namespaceRoles)
		stringSlice.Put(scopes)
		stringSlice.Put(allowedRoles)
		principalRoleSlice.Put(principalTenantRole)
		principalRoleSlice.Put(principalNamespaceScopeRole)
	}()

	mod, modExists := principalRoles.Tenant.Namespaces.Get(namespace)
	_, entExists := principalRoles.Tenant.Scopes.Get(scope)
	if (scope != "" && !entExists) || (namespace != "" && !modExists) {
		return nil
	}

	if modExists {
		mod.Scopes.ForEach(func(id string, _ *Scope) bool {
			namespaceScopes = append(namespaceScopes, id)
			return true
		})
		mod.Roles.ForEach(func(id string, _ *Role) bool {
			namespaceRoles = append(namespaceRoles, id)
			return true
		})
	}

	for _, principalRole := range principalRoles.Roles {
		if principalRole.Scope != nil {
			scopes = append(scopes, principalRole.Scope.ID)
		}
		if principalRole.Namespace != nil && principalRole.Scope != nil { // if role for namespace and scope
			principalNamespaceScopeRole = append(principalNamespaceScopeRole, principalRole)
		} else if principalRole.Namespace == nil && principalRole.Scope == nil { // if role for tenant
			principalTenantRole = append(principalTenantRole, principalRole)
		}
	}

	if len(namespaceRoles) > 0 {
		for _, modRole := range namespaceRoles {
			allowedRoles = append(allowedRoles, modRole)
		}
	} else {
		for _, r := range principalTenantRole {
			allowedRoles = append(allowedRoles, r.RoleID)
		}
	}

	noTenantScopes := !slices.Contains(scopes, scope) && len(principalTenantRole) == 0
	noNamespaceScopes := len(namespaceScopes) > 0 && !slices.Contains(namespaceScopes, scope)
	if noTenantScopes || noNamespaceScopes {
		return nil
	}

	if namespace != "" && scope != "" && len(principalNamespaceScopeRole) > 0 {
		for _, r := range principalNamespaceScopeRole {
			if r.Namespace.ID == namespace && r.Scope.ID == scope {
				allowedRoles = append(allowedRoles, r.RoleID)
			}
		}
	}

	for _, role := range allowedRoles {
		if _, ok := principalRoles.Tenant.Roles.Get(role); !ok {
			return nil
		}
	}
	return slices.Compact(allowedRoles)
}

func DefaultRoleManager() *RoleManager {
	return roleManager
}
