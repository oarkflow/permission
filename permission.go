package permission

import (
	"github.com/oarkflow/maps"
)

func Can(userID, tenant, module, entity, group, activity string) bool {
	var allowed []string
	if tenant == "" {
		return false
	}
	tenantUser := GetUserRoles(tenant, userID)
	if tenantUser == nil {
		return false
	}
	var userRoles []*Role
	roles := GetAllowedRoles(tenantUser, module, entity)
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
		if role.Has(group, activity, allowed...) {
			return true
		}
	}
	return false
}
func AddRole(role *Role) {
	roleManager.roles.Set(role.ID, role)
}
func GetRole(role string) (*Role, bool) {
	return roleManager.roles.Get(role)
}
func Roles() map[string]*Role {
	return roleManager.roles.AsMap()
}
func AddUserRole(userID string, roleID string, tenant *Tenant, module *Module, entity *Entity) {
	roleManager.AddUserRole(userID, roleID, tenant, module, entity)
}
func GetTenantUserRoles(tenant string) *TenantUser {
	return roleManager.GetTenantUserRoles(tenant)
}
func GetUserRoles(tenant, userID string) *TenantUser {
	return roleManager.GetUserRoles(tenant, userID)
}
func GetUserRolesByTenant(tenant string) []*UserRole {
	return roleManager.GetUserRolesByTenant(tenant)
}
func GetUserRoleByTenantAndUser(tenant, userID string) (ut []*UserRole) {
	return roleManager.GetUserRoleByTenantAndUser(tenant, userID)
}
func GetAllowedRoles(userRoles *TenantUser, module, entity string) []string {
	return roleManager.GetAllowedRoles(userRoles, module, entity)
}
func AddTenant(data *Tenant) {
	roleManager.AddTenant(data)
}
func GetTenant(id string) (*Tenant, bool) {
	return roleManager.GetTenant(id)
}
func Tenants() map[string]*Tenant {
	return roleManager.Tenants()
}
func AddModule(data *Module) {
	roleManager.AddModule(data)
}
func GetModule(id string) (*Module, bool) {
	return roleManager.GetModule(id)
}
func Modules() map[string]*Module {
	return roleManager.Modules()
}
func AddUser(data *User) {
	roleManager.AddUser(data)
}
func GetUser(id string) (*User, bool) {
	return roleManager.GetUser(id)
}
func Users() map[string]*User {
	return roleManager.Users()
}
func AddEntity(data *Entity) {
	roleManager.AddEntity(data)
}
func GetEntity(id string) (*Entity, bool) {
	return roleManager.GetEntity(id)
}
func Entities() map[string]*Entity {
	return roleManager.Entities()
}
func NewTenant(id string) *Tenant {
	tenant := &Tenant{
		ID:          id,
		Modules:     maps.New[string, *Module](),
		Roles:       maps.New[string, *Role](),
		Entities:    maps.New[string, *Entity](),
		descendants: maps.New[string, *Tenant](),
	}
	AddTenant(tenant)
	return tenant
}
func NewModule(id string) *Module {
	module := &Module{
		ID:       id,
		Roles:    maps.New[string, *Role](),
		Entities: maps.New[string, *Entity](),
	}
	AddModule(module)
	return module
}
func NewEntity(id string) *Entity {
	entity := &Entity{ID: id}
	AddEntity(entity)
	return entity
}
func NewRole(id string, lock ...bool) *Role {
	var disable bool
	if len(lock) > 0 {
		disable = lock[0]
	}
	role := &Role{
		ID:          id,
		permissions: maps.New[string, *AttributeGroup](),
		descendants: maps.New[string, *Role](),
		lock:        disable,
	}
	AddRole(role)
	return role
}
func NewAttribute(resource, action string) Attribute {
	return Attribute{
		Resource: resource,
		Action:   action,
	}
}
func NewUser(id string) *User {
	user := &User{ID: id}
	AddUser(user)
	return user
}
