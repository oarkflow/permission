package permission

import (
	"fmt"

	"github.com/oarkflow/maps"
)

type Tenant struct {
	namespaces       maps.IMap[string, *Namespace]
	roles            maps.IMap[string, *Role]
	scopes           maps.IMap[string, *Scope]
	descendants      maps.IMap[string, *Tenant]
	defaultNamespace *Namespace
	manager          *RoleManager
	id               string
}

func (c *Tenant) ID() string {
	return c.id
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
		if _, ok := c.descendants.Get(descendant.id); !ok {
			c.descendants.Set(descendant.id, descendant)
		}
	}
	return nil
}

func (c *Tenant) SetDefaultNamespace(namespace string) {
	if mod, ok := c.namespaces.Get(namespace); ok {
		c.defaultNamespace = mod
	}
}

func (c *Tenant) AddNamespace(namespaces ...*Namespace) {
	for _, namespace := range namespaces {
		if _, ok := c.namespaces.Get(namespace.id); !ok {
			c.namespaces.Set(namespace.id, namespace)
		}
	}
}

func (c *Tenant) AddRole(roles ...*Role) {
	for _, role := range roles {
		if _, ok := c.roles.Get(role.id); !ok {
			c.roles.Set(role.id, role)
		}
	}
}

func (c *Tenant) AddScopes(scopes ...*Scope) {
	for _, scope := range scopes {
		if _, ok := c.scopes.Get(scope.id); !ok {
			c.scopes.Set(scope.id, scope)
		}
		if c.defaultNamespace != nil {
			if _, ok := c.defaultNamespace.scopes.Get(scope.id); !ok {
				c.defaultNamespace.scopes.Set(scope.id, scope)
			}
		}
	}
}

func (c *Tenant) AddScopesToNamespace(namespace string, scopes ...string) {
	for _, id := range scopes {
		scope, exists := c.scopes.Get(id)
		if !exists {
			return
		}
		if mod, ok := c.namespaces.Get(namespace); ok {
			if _, ok = mod.scopes.Get(id); !ok {
				mod.scopes.Set(id, scope)
			}
			c.AddPrincipalRole("", "", c, mod, scope)
		}
	}
}

func (c *Tenant) AddRolesToNamespace(namespace string, roles ...string) {
	for _, id := range roles {
		role, exists := c.roles.Get(id)
		if !exists {
			return
		}
		if mod, ok := c.namespaces.Get(namespace); ok {
			if _, ok = mod.roles.Get(id); !ok {
				mod.roles.Set(id, role)
			}
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
		if _, ok := c.roles.Get(role); ok {
			c.AddPrincipalRole(principal, role, c, nil, nil)
			if c.defaultNamespace != nil {
				c.AddPrincipalRole(principal, role, c, c.defaultNamespace, nil)
			}
		}
	}
}

func (c *Tenant) AddPrincipalInNamespace(principal, namespace string, roles ...string) {
	mod, exists := c.namespaces.Get(namespace)
	if !exists {
		return
	}
	if len(roles) > 0 {
		for _, r := range roles {
			if role, ok := c.roles.Get(r); ok {
				c.AddPrincipalRole(principal, role.id, c, mod, nil)
			}
		}
	} else {
		for _, ur := range c.manager.GetPrincipalRolesByTenant(c.id) {
			if ur.PrincipalID == principal {
				if ur.NamespaceID != "" && ur.NamespaceID != namespace {
					c.AddPrincipalRole(principal, ur.RoleID, c, mod, nil)
				}
			}
		}
		c.AddPrincipalRole(principal, "", c, mod, nil)
	}
}

func (c *Tenant) AssignScopesToPrincipal(principalID string, scopes ...string) {
	principal := c.manager.GetPrincipalRoles(c.id, principalID)
	if principal == nil {
		return
	}
	fmt.Println(principal)
	for _, id := range scopes {
		if scope, ok := c.scopes.Get(id); ok {
			for _, role := range principal {
				c.AddPrincipalRole(principalID, role.RoleID, c, nil, scope)
				if c.defaultNamespace != nil {
					c.AddPrincipalRole(principalID, role.RoleID, c, c.defaultNamespace, scope)
				}
			}
			c.AddPrincipalRole(principalID, "", c, nil, scope)
		}
	}
}

func (c *Tenant) AssignScopesWithRole(principalID, roleId string, scopes ...string) {
	if len(scopes) == 0 {
		return
	}
	principal := c.manager.GetPrincipalRoles(c.id, principalID)
	if principal == nil {
		return
	}
	_, ok := c.roles.Get(roleId)
	if !ok {
		return
	}
	for _, id := range scopes {
		if scope, ok := c.scopes.Get(id); ok {
			c.AddPrincipalRole(principalID, roleId, c, nil, scope)
			if c.defaultNamespace != nil {
				c.AddPrincipalRole(principalID, roleId, c, c.defaultNamespace, scope)
			}
		}
	}
}

type Namespace struct {
	roles  maps.IMap[string, *Role]
	scopes maps.IMap[string, *Scope]
	id     string
}

func (n *Namespace) ID() string {
	return n.id
}

func (n *Namespace) AddRoles(roles ...*Role) {
	for _, role := range roles {
		n.roles.Set(role.id, role)
	}
}

func (n *Namespace) AddScopes(scopes ...*Scope) {
	for _, scope := range scopes {
		n.scopes.Set(scope.id, scope)
	}
}

type Scope struct {
	id string
}

func (s *Scope) ID() string {
	return s.id
}
