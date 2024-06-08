package permission

import (
	"github.com/oarkflow/permission/maps"
	"github.com/oarkflow/permission/trie"
)

type RoleManager struct {
	tenants         maps.IMap[string, *Tenant]
	namespaces      maps.IMap[string, *Namespace]
	scopes          maps.IMap[string, *Scope]
	principals      maps.IMap[string, *Principal]
	roles           maps.IMap[string, *Role]
	attributes      maps.IMap[string, *Attribute]
	attributeGroups maps.IMap[string, *AttributeGroup]
	trie            *trie.Trie
}

func New() *RoleManager {
	return &RoleManager{
		tenants:         maps.New[string, *Tenant](),
		namespaces:      maps.New[string, *Namespace](),
		scopes:          maps.New[string, *Scope](),
		principals:      maps.New[string, *Principal](),
		roles:           maps.New[string, *Role](),
		attributes:      maps.New[string, *Attribute](),
		attributeGroups: maps.New[string, *AttributeGroup](),
		trie:            trie.New(),
	}
}

func (u *RoleManager) Data() *trie.Trie {
	return u.trie
}

func getNamespaceIDs(rs []*trie.Data) (data []any) {
	for _, r := range rs {
		if r.NamespaceID != nil {
			data = append(data, r.NamespaceID)
		}
	}
	return
}

func getScopeIDs(rs []*trie.Data) (data []any) {
	for _, r := range rs {
		if r.ScopeID != nil {
			data = append(data, r.ScopeID)
		}
	}
	return
}

func (u *RoleManager) AddData(tenantID, namespaceID, scopeID, principalID, roleID, canManageDescendants any) {
	data := trie.AddData(tenantID, namespaceID, scopeID, principalID, roleID, canManageDescendants)
	u.trie.Insert(&data)
}

func (u *RoleManager) TotalRoles() uintptr {
	return u.roles.Len()
}

func (u *RoleManager) TotalNamespaces() uintptr {
	return u.namespaces.Len()
}

func (u *RoleManager) TotalScopes() uintptr {
	return u.scopes.Len()
}

func (u *RoleManager) TotalTenants() uintptr {
	return u.tenants.Len()
}

func (u *RoleManager) TotalPrincipals() uintptr {
	return u.principals.Len()
}
