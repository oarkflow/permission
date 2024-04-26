package permission

import (
	"slices"

	"github.com/oarkflow/maps"
)

var roleManager *RoleManager

func init() {
	roleManager = NewRoleManager()
}

// User represents a user with a role
type User struct {
	ID      string
	manager *RoleManager
}

// Can check if a user is allowed to do an activity based on their role and inherited permissions
func (u *User) Can(tenant, module, entity, group, activity string) bool {
	return Can(u.ID, tenant, module, entity, group, activity, u.manager)
}

type UserRole struct {
	UserID               string
	RoleID               string
	CanManageDescendants bool
	Tenant               *Tenant
	Module               *Module
	Entity               *Entity
}

type TenantUser struct {
	Tenant               *Tenant
	User                 *User
	CanManageDescendants bool
	Roles                []*UserRole
}

type RoleManager struct {
	tenants     maps.IMap[string, *Tenant]
	modules     maps.IMap[string, *Module]
	entities    maps.IMap[string, *Entity]
	users       maps.IMap[string, *User]
	roles       maps.IMap[string, *Role]
	tenantUsers maps.IMap[string, *TenantUser]
}

func NewRoleManager() *RoleManager {
	return &RoleManager{
		tenants:     maps.New[string, *Tenant](),
		modules:     maps.New[string, *Module](),
		entities:    maps.New[string, *Entity](),
		users:       maps.New[string, *User](),
		roles:       maps.New[string, *Role](),
		tenantUsers: maps.New[string, *TenantUser](),
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

func (u *RoleManager) AddModule(data *Module) {
	u.modules.Set(data.ID, data)
}

func (u *RoleManager) GetModule(id string) (*Module, bool) {
	return u.modules.Get(id)
}

func (u *RoleManager) Modules() map[string]*Module {
	return u.modules.AsMap()
}

func (u *RoleManager) AddUser(data *User) {
	u.users.Set(data.ID, data)
}

func (u *RoleManager) GetUser(id string) (*User, bool) {
	return u.users.Get(id)
}

func (u *RoleManager) Users() map[string]*User {
	return u.users.AsMap()
}

func (u *RoleManager) AddEntity(data *Entity) {
	u.entities.Set(data.ID, data)
}

func (u *RoleManager) GetEntity(id string) (*Entity, bool) {
	return u.entities.Get(id)
}

func (u *RoleManager) Entities() map[string]*Entity {
	return u.entities.AsMap()
}

func (u *RoleManager) AddUserRole(userID string, roleID string, tenant *Tenant, module *Module, entity *Entity, canManageDescendants ...bool) {
	manageDescendants := true
	if len(canManageDescendants) > 0 {
		manageDescendants = canManageDescendants[0]
	}
	role := &UserRole{
		UserID:               userID,
		RoleID:               roleID,
		Tenant:               tenant,
		Module:               module,
		Entity:               entity,
		CanManageDescendants: manageDescendants,
	}
	tenantUser, ok := u.tenantUsers.Get(tenant.ID)
	if !ok {
		tenantUser = &TenantUser{
			Tenant:               tenant,
			User:                 &User{ID: userID},
			CanManageDescendants: manageDescendants,
		}
	}
	tenantUser.Roles = append(tenantUser.Roles, role)
	u.tenantUsers.Set(tenant.ID, tenantUser)
}

func (u *RoleManager) GetTenantUserRoles(tenant string) *TenantUser {
	userRoles, ok := u.tenantUsers.Get(tenant)
	if !ok {
		return nil
	}
	return userRoles
}

func (u *RoleManager) GetUserRoles(tenant, userID string) *TenantUser {
	userRoles, ok := u.tenantUsers.Get(tenant)
	if !ok {
		return nil
	}
	roles := make([]*UserRole, 0, len(userRoles.Roles))
	userFound := false
	for _, ut := range userRoles.Roles {
		if ut.UserID == userID {
			userFound = true
			roles = append(roles, ut)
		}
	}
	if !userFound {
		return nil
	}
	return &TenantUser{
		Tenant:               userRoles.Tenant,
		User:                 userRoles.User,
		CanManageDescendants: userRoles.CanManageDescendants,
		Roles:                roles,
	}
}

func (u *RoleManager) GetUserRolesByTenant(tenant string) []*UserRole {
	userRoles, ok := u.tenantUsers.Get(tenant)
	if !ok {
		return nil
	}
	return userRoles.Roles
}

func (u *RoleManager) GetUserRoleByTenantAndUser(tenant, userID string) (ut []*UserRole) {
	userRoles, ok := u.tenantUsers.Get(tenant)
	if !ok {
		return
	}
	for _, ur := range userRoles.Roles {
		if ur.UserID == userID {
			ut = append(ut, ur)
		}
	}
	return
}

func (u *RoleManager) GetAllowedRoles(userRoles *TenantUser, module, entity string) []string {
	if userRoles == nil {
		return nil
	}
	// Reusable slices
	moduleEntities := stringSlice.Get()
	moduleRoles := stringSlice.Get()
	entities := stringSlice.Get()
	allowedRoles := stringSlice.Get()
	userTenantRole := userRoleSlice.Get()
	userModuleEntityRole := userRoleSlice.Get()
	defer func() {
		stringSlice.Put(moduleEntities)
		stringSlice.Put(moduleRoles)
		stringSlice.Put(entities)
		stringSlice.Put(allowedRoles)
		userRoleSlice.Put(userTenantRole)
		userRoleSlice.Put(userModuleEntityRole)
	}()

	mod, modExists := userRoles.Tenant.Modules.Get(module)
	_, entExists := userRoles.Tenant.Entities.Get(entity)
	if (entity != "" && !entExists) || (module != "" && !modExists) {
		return nil
	}

	if modExists {
		mod.Entities.ForEach(func(id string, _ *Entity) bool {
			moduleEntities = append(moduleEntities, id)
			return true
		})
		mod.Roles.ForEach(func(id string, _ *Role) bool {
			moduleRoles = append(moduleRoles, id)
			return true
		})
	}

	for _, userRole := range userRoles.Roles {
		if userRole.Entity != nil {
			entities = append(entities, userRole.Entity.ID)
		}
		if userRole.Module != nil && userRole.Entity != nil { // if role for module and entity
			userModuleEntityRole = append(userModuleEntityRole, userRole)
		} else if userRole.Module == nil && userRole.Entity == nil { // if role for tenant
			userTenantRole = append(userTenantRole, userRole)
		}
	}

	if len(moduleRoles) > 0 {
		for _, modRole := range moduleRoles {
			allowedRoles = append(allowedRoles, modRole)
		}
	} else {
		for _, r := range userTenantRole {
			allowedRoles = append(allowedRoles, r.RoleID)
		}
	}

	noTenantEntities := !slices.Contains(entities, entity) && len(userTenantRole) == 0
	noModuleEntities := len(moduleEntities) > 0 && !slices.Contains(moduleEntities, entity)
	if noTenantEntities || noModuleEntities {
		return nil
	}

	if module != "" && entity != "" && len(userModuleEntityRole) > 0 {
		for _, r := range userModuleEntityRole {
			if r.Module.ID == module && r.Entity.ID == entity {
				allowedRoles = append(allowedRoles, r.RoleID)
			}
		}
	}

	for _, role := range allowedRoles {
		if _, ok := userRoles.Tenant.Roles.Get(role); !ok {
			return nil
		}
	}
	return slices.Compact(allowedRoles)
}

func DefaultRoleManager() *RoleManager {
	return roleManager
}
