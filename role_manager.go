package permission

import (
	"slices"

	"github.com/oarkflow/maps"
)

// Principal represents a user with a role
type Principal struct {
	ID string
}

type PrincipalRole struct {
	Tenant               *Tenant
	Namespace            *Namespace
	Scope                *Scope
	PrincipalID          string
	RoleID               string
	CanManageDescendants bool
}

type TenantPrincipal struct {
	Tenant               *Tenant
	Principal            *Principal
	Roles                []*PrincipalRole
	CanManageDescendants bool
}

type RoleManager struct {
	tenants          maps.IMap[string, *Tenant]
	namespaces       maps.IMap[string, *Namespace]
	scopes           maps.IMap[string, *Scope]
	principals       maps.IMap[string, *Principal]
	roles            maps.IMap[string, *Role]
	tenantPrincipals maps.IMap[string, *TenantPrincipal]
	attributes       maps.IMap[string, *Attribute]
}

func New() *RoleManager {
	return &RoleManager{
		tenants:          maps.New[string, *Tenant](),
		namespaces:       maps.New[string, *Namespace](),
		scopes:           maps.New[string, *Scope](),
		principals:       maps.New[string, *Principal](),
		roles:            maps.New[string, *Role](),
		tenantPrincipals: maps.New[string, *TenantPrincipal](),
		attributes:       maps.New[string, *Attribute](),
	}
}

func (u *RoleManager) AddAttribute(attr *Attribute) *Attribute {
	u.attributes.GetOrSet(attr.String(), attr)
	return attr
}

func (u *RoleManager) AddAttributes(attrs ...*Attribute) {
	for _, attr := range attrs {
		u.AddAttribute(attr)
	}
}

func (u *RoleManager) GetAttribute(attr string) (*Attribute, bool) {
	return u.attributes.Get(attr)
}

func (u *RoleManager) TotalAttributes() uintptr {
	return u.attributes.Len()
}

func (u *RoleManager) TotalRoles() uintptr {
	return u.roles.Len()
}

func (u *RoleManager) TotalNamespaces() uintptr {
	return u.namespaces.Len()
}

func (u *RoleManager) TotalScopes() uintptr {
	return u.scopes.Len()
}

func (u *RoleManager) TotalTenants() uintptr {
	return u.tenants.Len()
}

func (u *RoleManager) TotalPrincipals() uintptr {
	return u.principals.Len()
}

func (u *RoleManager) Attributes() map[string]*Attribute {
	return u.attributes.AsMap()
}

func (u *RoleManager) AddRole(role *Role) *Role {
	u.roles.GetOrSet(role.ID, role)
	return role
}

func (u *RoleManager) AddRoles(roles ...*Role) {
	for _, role := range roles {
		u.AddRole(role)
	}
}

func (u *RoleManager) GetRole(role string) (*Role, bool) {
	return u.roles.Get(role)
}

func (u *RoleManager) Roles() map[string]*Role {
	return u.roles.AsMap()
}

func (u *RoleManager) AddTenant(data *Tenant) *Tenant {
	data.manager = u
	u.tenants.GetOrSet(data.ID, data)
	return data
}

func (u *RoleManager) AddTenants(tenants ...*Tenant) {
	for _, data := range tenants {
		u.AddTenant(data)
	}
}

func (u *RoleManager) GetTenant(id string) (*Tenant, bool) {
	return u.tenants.Get(id)
}

func (u *RoleManager) Tenants() map[string]*Tenant {
	return u.tenants.AsMap()
}

func (u *RoleManager) AddNamespace(data *Namespace) *Namespace {
	u.namespaces.GetOrSet(data.ID, data)
	return data
}

func (u *RoleManager) AddNamespaces(nms ...*Namespace) {
	for _, data := range nms {
		u.AddNamespace(data)
	}
}

func (u *RoleManager) GetNamespace(id string) (*Namespace, bool) {
	return u.namespaces.Get(id)
}

func (u *RoleManager) Namespaces() map[string]*Namespace {
	return u.namespaces.AsMap()
}

func (u *RoleManager) AddPrincipal(data *Principal) *Principal {
	u.principals.GetOrSet(data.ID, data)
	return data
}

func (u *RoleManager) AddPrincipals(principals ...*Principal) {
	for _, data := range principals {
		u.AddPrincipal(data)
	}
}

func (u *RoleManager) GetPrincipal(id string) (*Principal, bool) {
	return u.principals.Get(id)
}

func (u *RoleManager) Principals() map[string]*Principal {
	return u.principals.AsMap()
}

func (u *RoleManager) AddScope(data *Scope) *Scope {
	u.scopes.GetOrSet(data.ID, data)
	return data
}

func (u *RoleManager) AddScopes(scopes ...*Scope) {
	for _, data := range scopes {
		u.AddScope(data)
	}
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
	u.tenantPrincipals.GetOrSet(tenant.ID, tenantPrincipal)
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

func (u *RoleManager) GetRolesForPrincipalByTenant(tenant, principalID string) (ut []*PrincipalRole) {
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

func (u *RoleManager) Authorize(principalID string, options ...func(*Option)) bool {
	svr := &Option{}
	for _, o := range options {
		o(svr)
	}
	_, exists := u.GetPrincipal(principalID)
	if !exists {
		return false
	}

	if svr.tenant == "" {
		return false
	}
	_, exists = u.GetTenant(svr.tenant)
	if !exists {
		return false
	}
	var allowed []string
	tenantPrincipal := u.GetPrincipalRoles(svr.tenant, principalID)
	if tenantPrincipal == nil {
		return false
	}
	var principalRoles []*Role
	roles := u.GetAllowedRoles(tenantPrincipal, svr.namespace, svr.scope)
	tenantPrincipal.Tenant.Roles.ForEach(func(_ string, r *Role) bool {
		for _, rt := range roles {
			if r.ID == rt {
				principalRoles = append(principalRoles, r)
			}
		}
		allowed = append(allowed, r.ID)
		return true
	})
	for _, role := range principalRoles {
		if role.Has(svr.resourceGroup, svr.activity, allowed...) {
			return true
		}
	}
	return false
}
