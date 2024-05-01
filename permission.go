package permission

import (
	"github.com/oarkflow/maps"
)

func Can(principalID string, options ...func(*Option)) bool {
	svr := &Option{}
	for _, o := range options {
		o(svr)
	}
	manager := getRoleManager(svr.manager)
	_, exists := manager.GetPrincipal(principalID)
	if !exists {
		return false
	}

	if svr.tenant == "" {
		return false
	}
	_, exists = manager.GetTenant(svr.tenant)
	if !exists {
		return false
	}
	var allowed []string
	tenantPrincipal := manager.GetPrincipalRoles(svr.tenant, principalID)
	if tenantPrincipal == nil {
		return false
	}
	var principalRoles []*Role
	roles := manager.GetAllowedRoles(tenantPrincipal, svr.namespace, svr.scope)
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

func NewTenant(id string, managers ...*RoleManager) *Tenant {
	tenant := &Tenant{
		ID:          id,
		Namespaces:  maps.New[string, *Namespace](),
		Roles:       maps.New[string, *Role](),
		Scopes:      maps.New[string, *Scope](),
		descendants: maps.New[string, *Tenant](),
		manager:     getRoleManager(managers...),
	}
	tenant.manager.AddTenant(tenant)
	return tenant
}
func NewNamespace(id string, managers ...*RoleManager) *Namespace {
	namespace := &Namespace{
		ID:      id,
		Roles:   maps.New[string, *Role](),
		Scopes:  maps.New[string, *Scope](),
		manager: getRoleManager(managers...),
	}
	namespace.manager.AddNamespace(namespace)
	return namespace
}
func NewScope(id string, managers ...*RoleManager) *Scope {
	scope := &Scope{
		ID:      id,
		manager: getRoleManager(managers...),
	}
	scope.manager.AddScope(scope)
	return scope
}
func NewRole(id string, managers ...*RoleManager) *Role {
	role := &Role{
		ID:          id,
		permissions: maps.New[string, *AttributeResourceGroup](),
		descendants: maps.New[string, *Role](),
		manager:     getRoleManager(managers...),
	}
	role.manager.AddRole(role)
	return role
}
func NewAttribute(resource, action string) Attribute {
	return Attribute{
		Resource: resource,
		Action:   action,
	}
}
func NewPrincipal(id string, managers ...*RoleManager) *Principal {
	principal := &Principal{
		ID:      id,
		manager: getRoleManager(managers...),
	}
	principal.manager.AddPrincipal(principal)
	return principal
}

func getRoleManager(managers ...*RoleManager) *RoleManager {
	if len(managers) > 0 && managers[0] != nil {
		return managers[0]
	}
	return roleManager
}
