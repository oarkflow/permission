package permission

import (
	"errors"

	"github.com/oarkflow/permission/maps"
)

func WithTenant(tenant any) func(*Option) {
	return func(s *Option) {
		s.tenant = tenant
	}
}

type Tenant struct {
	descendants      maps.IMap[string, *Tenant]
	defaultNamespace *Namespace
	manager          *RoleManager
	id               string
}

func (c *Tenant) ID() string {
	return c.id
}

func (c *Tenant) AddNamespace(n *Namespace) *Namespace {
	c.manager.AddData(c.id, n.id, nil, nil, nil, nil)
	return n
}

func (c *Tenant) GetDescendants() (data []any) {
	c.descendants.ForEach(func(id string, t *Tenant) bool {
		data = append(data, id)
		data = append(data, t.GetDescendants()...)
		return true
	})
	return
}

func (c *Tenant) AddDescendant(descendants ...*Tenant) error {
	for _, descendant := range descendants {
		if _, ok := c.descendants.Get(descendant.id); !ok {
			c.descendants.Set(descendant.id, descendant)
		}
		if c.defaultNamespace != nil {
			descendant.AddNamespace(c.defaultNamespace)
			descendant.SetDefaultNamespace(c.defaultNamespace.id)
		}
	}
	return nil
}

func (c *Tenant) AddNamespaces(nms ...*Namespace) {
	for _, n := range nms {
		c.AddNamespace(n)
	}
}

func (c *Tenant) SetDefaultNamespace(nms string) {
	if n, ok := c.manager.namespaces.Get(nms); ok {
		c.defaultNamespace = n
	}
}

func (c *Tenant) AddRole(n *Role) *Role {
	c.manager.AddData(c.id, nil, nil, nil, n.id, nil)
	return n
}

func (c *Tenant) AddRoles(nms ...*Role) {
	for _, n := range nms {
		c.AddRole(n)
	}
}

func (c *Tenant) AddScope(n *Scope) *Scope {
	c.manager.AddData(c.id, nil, n.id, nil, nil, nil)
	return n
}

func (c *Tenant) AddScopes(nms ...*Scope) {
	for _, n := range nms {
		c.AddScope(n)
	}
}

func (c *Tenant) AddPrincipalWithRole(principalID, roleID string) error {
	if _, ok := c.manager.principals.Get(principalID); !ok {
		return errors.New("no principal available")
	}
	if _, ok := c.manager.roles.Get(roleID); !ok {
		return errors.New("no role available")
	}
	c.manager.AddData(c.id, nil, nil, principalID, roleID, true)
	if c.defaultNamespace != nil {
		c.manager.AddData(c.id, c.defaultNamespace.id, nil, principalID, roleID, true)
	}
	return nil
}

func (c *Tenant) AddPrincipal(principalID string, nms ...string) error {
	for _, n := range nms {
		err := c.AddPrincipalWithRole(principalID, n)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Tenant) AddScopeToPrincipal(principalID, scopeID string) error {
	if _, ok := c.manager.principals.Get(principalID); !ok {
		return errors.New("no principal available")
	}
	if _, ok := c.manager.scopes.Get(scopeID); !ok {
		return errors.New("no scope available")
	}
	c.manager.AddData(c.id, nil, scopeID, principalID, nil, true)
	if c.defaultNamespace != nil {
		c.manager.AddData(c.id, c.defaultNamespace.id, scopeID, principalID, nil, true)
	}
	return nil
}

func (c *Tenant) AssignScopesToPrincipal(principalID string, nms ...string) error {
	for _, n := range nms {
		err := c.AddScopeToPrincipal(principalID, n)
		if err != nil {
			return err
		}
	}
	return nil
}

func (u *RoleManager) AddTenant(data *Tenant) *Tenant {
	data.manager = u
	if d, ok := u.tenants.Get(data.id); ok {
		return d
	}
	u.tenants.Set(data.id, data)
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

func (u *RoleManager) Tenants() (data []string) {
	u.tenants.ForEach(func(id string, _ *Tenant) bool {
		data = append(data, id)
		return true
	})
	return
}
