package permission

import (
	maps "github.com/oarkflow/xsync"
)

func NewTenant(id string) *Tenant {
	return &Tenant{
		id:          id,
		descendants: maps.NewMap[string, *Tenant](),
	}
}
func NewNamespace(id string) *Namespace {
	return &Namespace{
		id: id,
	}
}
func NewScope(id string) *Scope {
	return &Scope{
		id: id,
	}
}

func NewRole(id string) *Role {
	return &Role{
		id:          id,
		permissions: maps.NewMap[string, *AttributeGroup](),
		descendants: maps.NewMap[string, *Role](),
	}
}

func NewAttributeGroup(id string) *AttributeGroup {
	return &AttributeGroup{
		id:          id,
		permissions: maps.NewMap[string, *Attribute](),
	}
}

func NewAttributes(resource string, actions ...string) (attrs []*Attribute) {
	for _, action := range actions {
		attrs = append(attrs, NewAttribute(resource, action))
	}
	return
}

func NewAttribute(resource string, action string) *Attribute {
	return &Attribute{
		resource: resource,
		action:   action,
	}
}
func NewPrincipal(id string) *Principal {
	return &Principal{
		id: id,
	}
}

func (u *RoleManager) AddRole(role *Role) *Role {
	if r, exists := u.roles.Get(role.id); exists {
		return r
	}
	u.roles.Set(role.id, role)
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

func (u *RoleManager) Roles() (data []string) {
	u.roles.ForEach(func(id string, _ *Role) bool {
		data = append(data, id)
		return true
	})
	return
}

type AttributeResponse struct {
	Attribute Attribute `json:"attribute"`
	Roles     []string  `json:"roles"`
}

func (u *RoleManager) GetRolesForAvailablePermissions() map[string][]AttributeResponse {
	response := make(map[string][]AttributeResponse)
	seen := make(map[string]map[Attribute][]string)
	u.roles.ForEach(func(_ string, role *Role) bool {
		for group, permissions := range role.GetAllImplicitPermissions() {
			groupPermissions, ok := seen[group]
			if !ok {
				groupPermissions = make(map[Attribute][]string)
			}
			for _, permission := range permissions {
				groupPermissions[permission] = append(groupPermissions[permission], role.id)
			}
			seen[group] = groupPermissions
		}
		return true
	})
	for category, attributeRoles := range seen {
		for attribute, roles := range attributeRoles {
			response[category] = append(response[category], AttributeResponse{
				Attribute: attribute,
				Roles:     roles,
			})
		}
	}
	clear(seen)
	return response
}
