package permission

import (
	"github.com/oarkflow/maps"
)

func NewTenant(id string) *Tenant {
	tenant := &Tenant{
		ID:          id,
		Namespaces:  maps.New[string, *Namespace](),
		Roles:       maps.New[string, *Role](),
		Scopes:      maps.New[string, *Scope](),
		descendants: maps.New[string, *Tenant](),
	}
	return tenant
}
func NewNamespace(id string) *Namespace {
	namespace := &Namespace{
		ID:     id,
		Roles:  maps.New[string, *Role](),
		Scopes: maps.New[string, *Scope](),
	}
	return namespace
}
func NewScope(id string) *Scope {
	scope := &Scope{
		ID: id,
	}
	return scope
}
func NewRole(id string) *Role {
	role := &Role{
		ID:          id,
		permissions: maps.New[string, *AttributeResourceGroup](),
		descendants: maps.New[string, *Role](),
	}
	return role
}
func NewAttribute(resource string, actions ...string) (attrs []Attribute) {
	for _, action := range actions {
		attrs = append(attrs, Attribute{
			Resource: resource,
			Action:   action,
		})
	}
	return
}
func NewPrincipal(id string) *Principal {
	principal := &Principal{
		ID: id,
	}
	return principal
}
