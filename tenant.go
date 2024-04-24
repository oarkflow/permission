package permission

import (
	"github.com/oarkflow/maps"
)

type Tenant struct {
	ID            string
	defaultModule *Module
	Modules       maps.IMap[string, *Module]
	Roles         maps.IMap[string, *Role]
	Entities      maps.IMap[string, *Entity]
	descendants   maps.IMap[string, *Tenant]
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
		c.descendants.Set(descendant.ID, descendant)
	}
	return nil
}

func (c *Tenant) SetDefaultModule(module string) {
	if mod, ok := c.Modules.Get(module); ok {
		c.defaultModule = mod
	}
}

func (c *Tenant) AddModule(modules ...*Module) {
	for _, module := range modules {
		c.Modules.Set(module.ID, module)
	}
}

func (c *Tenant) AddRole(roles ...*Role) {
	for _, role := range roles {
		c.Roles.Set(role.ID, role)
	}
}

func (c *Tenant) AddEntities(entities ...*Entity) {
	for _, entity := range entities {
		c.Entities.Set(entity.ID, entity)
		if c.defaultModule != nil {
			c.defaultModule.Entities.Set(entity.ID, entity)
		}
	}
}

func (c *Tenant) AddEntitiesToModule(module string, entities ...string) {
	for _, id := range entities {
		entity, exists := c.Entities.Get(id)
		if !exists {
			return
		}
		if mod, ok := c.Modules.Get(module); ok {
			mod.Entities.Set(id, entity)
		} else {
			return
		}
	}
}

func (c *Tenant) AddRolesToModule(module string, roles ...string) {
	for _, id := range roles {
		role, exists := c.Roles.Get(id)
		if !exists {
			return
		}
		if mod, ok := c.Modules.Get(module); ok {
			mod.Roles.Set(id, role)
		} else {
			return
		}
	}
}

func (c *Tenant) AddUser(user, role string) {
	if _, ok := c.Roles.Get(role); ok {
		AddUserRole(user, role, c, nil, nil)
		if c.defaultModule != nil {
			AddUserRole(user, role, c, c.defaultModule, nil)
		}
	}
}

func (c *Tenant) AddUserInModule(user, module string, roles ...string) {
	mod, exists := c.Modules.Get(module)
	if !exists {
		return
	}
	if len(roles) > 0 {
		for _, r := range roles {
			if role, ok := c.Roles.Get(r); ok {
				AddUserRole(user, role.ID, c, mod, nil)
			}
		}
	} else {
		for _, ur := range GetUserRolesByTenant(c.ID) {
			if ur.UserID == user && ur.Module != nil && ur.Module.ID != module {
				AddUserRole(user, ur.RoleID, c, mod, nil)
			}
		}
	}
}

func (c *Tenant) AssignEntitiesToUser(userID string, entities ...string) {
	user := GetUserRoles(c.ID, userID)
	if user == nil {
		return
	}
	for _, role := range user.Roles {
		for _, id := range entities {
			if entity, ok := c.Entities.Get(id); ok {
				AddUserRole(userID, role.RoleID, c, nil, entity)
				if c.defaultModule != nil {
					AddUserRole(userID, role.RoleID, c, c.defaultModule, entity)
				}
			}
		}
	}
}

func (c *Tenant) AssignEntitiesWithRole(userID, roleId string, entities ...string) {
	if len(entities) == 0 {
		return
	}
	user := GetUserRoles(c.ID, userID)
	if user == nil {
		return
	}
	_, ok := c.Roles.Get(roleId)
	if !ok {
		return
	}
	for _, id := range entities {
		if entity, ok := c.Entities.Get(id); ok {
			AddUserRole(userID, roleId, c, nil, entity)
			if c.defaultModule != nil {
				AddUserRole(userID, roleId, c, c.defaultModule, entity)
			}
		}
	}
}

type Module struct {
	ID       string
	Roles    maps.IMap[string, *Role]
	Entities maps.IMap[string, *Entity]
}
type Entity struct {
	ID string
}
