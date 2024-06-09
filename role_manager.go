package permission

import (
	"encoding/json"

	"github.com/oarkflow/permission/maps"
	"github.com/oarkflow/permission/trie"
	"github.com/oarkflow/permission/utils"
)

type RoleManager struct {
	tenants         maps.IMap[string, *Tenant]
	namespaces      maps.IMap[string, *Namespace]
	scopes          maps.IMap[string, *Scope]
	principals      maps.IMap[string, *Principal]
	roles           maps.IMap[string, *Role]
	attributes      maps.IMap[string, *Attribute]
	attributeGroups maps.IMap[string, *AttributeGroup]
	trie            *trie.Trie[Data]
	hierarchy       maps.IMap[string, []any]
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
		trie:            trie.New[Data](FilterFunc),
		hierarchy:       maps.New[string, []any](),
	}
}

func (u *RoleManager) Data() *trie.Trie[Data] {
	return u.trie
}

func getNamespaceIDs(rs []*Data) (data []any) {
	for _, r := range rs {
		if r.Namespace != nil {
			data = append(data, r.Namespace)
		}
	}
	return
}

func getScopeIDs(rs []*Data) (data []any) {
	for _, r := range rs {
		if r.Scope != nil {
			data = append(data, r.Scope)
		}
	}
	return
}

func (u *RoleManager) AddData(data *Data) {
	u.trie.Insert(data)
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

func (u *RoleManager) TenantChildren(t string) []any {
	if hierarchy, exists := u.hierarchy.Get(t); exists {
		return hierarchy
	}
	tenant, exists := u.GetTenant(t)
	if !exists {
		return nil
	}
	hierarchy := tenant.GetDescendants()
	u.hierarchy.Set(t, utils.Compact(hierarchy))
	return hierarchy
}

func (u *RoleManager) TotalTenants() uintptr {
	return u.tenants.Len()
}

func (u *RoleManager) TotalPrincipals() uintptr {
	return u.principals.Len()
}

func (u *RoleManager) AsString() string {
	data, err := json.Marshal(u.trie.Data())
	if err != nil {
		return ""
	}
	return utils.FromByte(data)
}
