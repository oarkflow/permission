package permission

import (
	"github.com/oarkflow/maps"
)

func Can(userID string, options ...func(*Option)) bool {
	svr := &Option{userID: userID}
	for _, o := range options {
		o(svr)
	}
	manager := getRoleManager(svr.manager)
	var allowed []string
	if svr.tenant == "" {
		return false
	}
	tenantUser := manager.GetUserRoles(svr.tenant, userID)
	if tenantUser == nil {
		return false
	}
	var userRoles []*Role
	roles := manager.GetAllowedRoles(tenantUser, svr.module, svr.entity)
	tenantUser.Tenant.Roles.ForEach(func(_ string, r *Role) bool {
		for _, rt := range roles {
			if r.ID == rt {
				userRoles = append(userRoles, r)
			}
		}
		allowed = append(allowed, r.ID)
		return true
	})
	for _, role := range userRoles {
		if role.Has(svr.group, svr.activity, allowed...) {
			return true
		}
	}
	return false
}

func NewTenant(id string, managers ...*RoleManager) *Tenant {
	tenant := &Tenant{
		ID:          id,
		Modules:     maps.New[string, *Module](),
		Roles:       maps.New[string, *Role](),
		Entities:    maps.New[string, *Entity](),
		descendants: maps.New[string, *Tenant](),
		manager:     getRoleManager(managers...),
	}
	tenant.manager.AddTenant(tenant)
	return tenant
}
func NewModule(id string, managers ...*RoleManager) *Module {
	module := &Module{
		ID:       id,
		Roles:    maps.New[string, *Role](),
		Entities: maps.New[string, *Entity](),
		manager:  getRoleManager(managers...),
	}
	module.manager.AddModule(module)
	return module
}
func NewEntity(id string, managers ...*RoleManager) *Entity {
	entity := &Entity{
		ID:      id,
		manager: getRoleManager(managers...),
	}
	entity.manager.AddEntity(entity)
	return entity
}
func NewRole(id string, managers ...*RoleManager) *Role {
	role := &Role{
		ID:          id,
		permissions: maps.New[string, *AttributeGroup](),
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
func NewUser(id string, managers ...*RoleManager) *User {
	user := &User{
		ID:      id,
		manager: getRoleManager(managers...),
	}
	user.manager.AddUser(user)
	return user
}

func getRoleManager(managers ...*RoleManager) *RoleManager {
	if len(managers) > 0 && managers[0] != nil {
		return managers[0]
	}
	return roleManager
}
