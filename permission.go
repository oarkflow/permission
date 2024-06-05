package permission

import (
	"github.com/oarkflow/maps"
)

func NewTenant(id string) *Tenant {
	return &Tenant{
		id:          id,
		namespaces:  maps.New[string, *Namespace](),
		roles:       maps.New[string, *Role](),
		scopes:      maps.New[string, *Scope](),
		descendants: maps.New[string, *Tenant](),
	}
}
func NewNamespace(id string) *Namespace {
	return &Namespace{
		id:     id,
		roles:  maps.New[string, *Role](),
		scopes: maps.New[string, *Scope](),
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
		permissions: maps.New[string, *AttributeGroup](),
		descendants: maps.New[string, *Role](),
	}
}

func NewAttributeGroup(id string) *AttributeGroup {
	return &AttributeGroup{
		id:          id,
		permissions: maps.New[string, *Attribute](),
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
