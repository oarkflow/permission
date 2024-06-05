package permission

import (
	"github.com/oarkflow/maps"
)

func NewTenant(id string) *Tenant {
	return &Tenant{
		ID:          id,
		Namespaces:  maps.New[string, *Namespace](),
		Roles:       maps.New[string, *Role](),
		Scopes:      maps.New[string, *Scope](),
		descendants: maps.New[string, *Tenant](),
	}
}
func NewNamespace(id string) *Namespace {
	return &Namespace{
		ID:     id,
		Roles:  maps.New[string, *Role](),
		Scopes: maps.New[string, *Scope](),
	}
}
func NewScope(id string) *Scope {
	return &Scope{
		ID: id,
	}
}

func NewRole(id string) *Role {
	return &Role{
		ID:          id,
		permissions: maps.New[string, *AttributeGroup](),
		descendants: maps.New[string, *Role](),
	}
}

func NewAttributeGroup(id string) *AttributeGroup {
	return &AttributeGroup{
		ID:          id,
		permissions: maps.New[string, *Attribute](),
	}
}

func NewAttribute(resource string, actions ...string) (attrs []*Attribute) {
	for _, action := range actions {
		attrs = append(attrs, &Attribute{
			Resource: resource,
			Action:   action,
		})
	}
	return
}
func NewPrincipal(id string) *Principal {
	return &Principal{
		ID: id,
	}
}
