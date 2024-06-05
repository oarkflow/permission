package permission

import (
	"github.com/oarkflow/maps"
)

type Tenant struct {
	Namespaces       maps.IMap[string, *Namespace]
	Roles            maps.IMap[string, *Role]
	Scopes           maps.IMap[string, *Scope]
	descendants      maps.IMap[string, *Tenant]
	defaultNamespace *Namespace
	manager          *RoleManager
	ID               string
}

func (c *Tenant) GetDescendantTenants() []*Tenant {
	var descendants []*Tenant
	c.descendants.ForEach(func(_ string, child *Tenant) bool {
		descendants = append(descendants, child)
		descendants = append(descendants, child.GetDescendantTenants()...)
		return true
	})
	return descendants
}

// AddDescendent adds a new permission to the role
func (c *Tenant) AddDescendent(descendants ...*Tenant) error {
	for _, descendant := range descendants {
		c.descendants.GetOrSet(descendant.ID, descendant)
	}
	return nil
}

func (c *Tenant) SetDefaultNamespace(namespace string) {
	if mod, ok := c.Namespaces.Get(namespace); ok {
		c.defaultNamespace = mod
	}
}

func (c *Tenant) AddNamespace(namespaces ...*Namespace) {
	for _, namespace := range namespaces {
		c.Namespaces.GetOrSet(namespace.ID, namespace)
	}
}

func (c *Tenant) AddRole(roles ...*Role) {
	for _, role := range roles {
		c.Roles.GetOrSet(role.ID, role)
	}
}

func (c *Tenant) AddScopes(scopes ...*Scope) {
	for _, scope := range scopes {
		c.Scopes.GetOrSet(scope.ID, scope)
		if c.defaultNamespace != nil {
			c.defaultNamespace.Scopes.GetOrSet(scope.ID, scope)
		}
	}
}

func (c *Tenant) AddScopesToNamespace(namespace string, scopes ...string) {
	for _, id := range scopes {
		scope, exists := c.Scopes.Get(id)
		if !exists {
			return
		}
		if mod, ok := c.Namespaces.Get(namespace); ok {
			mod.Scopes.GetOrSet(id, scope)
		} else {
			return
		}
	}
}

func (c *Tenant) AddRolesToNamespace(namespace string, roles ...string) {
	for _, id := range roles {
		role, exists := c.Roles.Get(id)
		if !exists {
			return
		}
		if mod, ok := c.Namespaces.Get(namespace); ok {
			mod.Roles.GetOrSet(id, role)
		} else {
			return
		}
	}
}

func (c *Tenant) AddPrincipalRole(principalID string, roleID string, tenant *Tenant, namespace *Namespace, scope *Scope, canManageDescendants ...bool) {
	c.manager.AddPrincipalRole(principalID, roleID, tenant, namespace, scope, canManageDescendants...)
}

func (c *Tenant) AddPrincipal(principal string, roles ...string) {
	for _, role := range roles {
		if _, ok := c.Roles.Get(role); ok {
			c.AddPrincipalRole(principal, role, c, nil, nil)
			if c.defaultNamespace != nil {
				c.AddPrincipalRole(principal, role, c, c.defaultNamespace, nil)
			}
		}
	}
}

func (c *Tenant) AddPrincipalInNamespace(principal, namespace string, roles ...string) {
	mod, exists := c.Namespaces.Get(namespace)
	if !exists {
		return
	}
	if len(roles) > 0 {
		for _, r := range roles {
			if role, ok := c.Roles.Get(r); ok {
				c.AddPrincipalRole(principal, role.ID, c, mod, nil)
			}
		}
	} else {
		for _, ur := range c.manager.GetPrincipalRolesByTenant(c.ID) {
			if ur.PrincipalID == principal && ur.Namespace != nil && ur.Namespace.ID != namespace {
				c.AddPrincipalRole(principal, ur.RoleID, c, mod, nil)
			}
		}
	}
}

func (c *Tenant) AssignScopesToPrincipal(principalID string, scopes ...string) {
	principal := c.manager.GetPrincipalRoles(c.ID, principalID)
	if principal == nil {
		return
	}
	for _, role := range principal.Roles {
		for _, id := range scopes {
			if scope, ok := c.Scopes.Get(id); ok {
				c.AddPrincipalRole(principalID, role.RoleID, c, nil, scope)
				if c.defaultNamespace != nil {
					c.AddPrincipalRole(principalID, role.RoleID, c, c.defaultNamespace, scope)
				}
			}
		}
	}
}

func (c *Tenant) AssignScopesWithRole(principalID, roleId string, scopes ...string) {
	if len(scopes) == 0 {
		return
	}
	principal := c.manager.GetPrincipalRoles(c.ID, principalID)
	if principal == nil {
		return
	}
	_, ok := c.Roles.Get(roleId)
	if !ok {
		return
	}
	for _, id := range scopes {
		if scope, ok := c.Scopes.Get(id); ok {
			c.AddPrincipalRole(principalID, roleId, c, nil, scope)
			if c.defaultNamespace != nil {
				c.AddPrincipalRole(principalID, roleId, c, c.defaultNamespace, scope)
			}
		}
	}
}

type Namespace struct {
	Roles  maps.IMap[string, *Role]
	Scopes maps.IMap[string, *Scope]
	ID     string
}
type Scope struct {
	ID string
}
