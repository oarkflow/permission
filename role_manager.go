package permission

import (
	"encoding/json"

	maps "github.com/oarkflow/xsync"

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
	hierarchy       map[string][]any
	principalCache  map[string]map[string]struct{}
}

func New() *RoleManager {
	return &RoleManager{
		tenants:         maps.NewMap[string, *Tenant](),
		namespaces:      maps.NewMap[string, *Namespace](),
		scopes:          maps.NewMap[string, *Scope](),
		principals:      maps.NewMap[string, *Principal](),
		roles:           maps.NewMap[string, *Role](),
		attributes:      maps.NewMap[string, *Attribute](),
		attributeGroups: maps.NewMap[string, *AttributeGroup](),
		trie:            trie.New[Data](FilterFunc),
		hierarchy:       make(map[string][]any),
		principalCache:  make(map[string]map[string]struct{}),
	}
}

func (u *RoleManager) Data() *trie.Trie[Data] {
	return u.trie
}

func GetTenantIDs(rs []*Data) (data []any) {
	seen := make(map[any]struct{})
	for _, r := range rs {
		if _, ok := seen[r.Tenant]; !ok {
			seen[r.Tenant] = struct{}{}
			data = append(data, r.Tenant)
		}
	}
	clear(seen)
	return
}

func GetPrincipalIDs(rs []*Data) (data []any) {
	seen := make(map[any]struct{})
	for _, r := range rs {
		if _, ok := seen[r.Principal]; !ok {
			seen[r.Principal] = struct{}{}
			data = append(data, r.Principal)
		}
	}
	clear(seen)
	return
}

func GetRoleIDs(rs []*Data) (data []any) {
	seen := make(map[any]struct{})
	for _, r := range rs {
		if _, ok := seen[r.Role]; !ok {
			seen[r.Role] = struct{}{}
			data = append(data, r.Role)
		}
	}
	clear(seen)
	return
}

func GetNamespaceIDs(rs []*Data) (data []any) {
	seen := make(map[any]struct{})
	for _, r := range rs {
		if _, ok := seen[r.Namespace]; !ok {
			seen[r.Namespace] = struct{}{}
			data = append(data, r.Namespace)
		}
	}
	clear(seen)
	return
}

func GetScopeIDs(rs []*Data) (data []any) {
	seen := make(map[any]struct{})
	for _, r := range rs {
		if _, ok := seen[r.Scope]; !ok {
			seen[r.Scope] = struct{}{}
			data = append(data, r.Scope)
		}
	}
	clear(seen)
	return
}

func (u *RoleManager) AddData(data *Data) {
	u.trie.Insert(data)
}

func (u *RoleManager) TotalRoles() int {
	return u.roles.Size()
}

func (u *RoleManager) TotalNamespaces() int {
	return u.namespaces.Size()
}

func (u *RoleManager) TotalScopes() int {
	return u.scopes.Size()
}

func (u *RoleManager) TenantChildren(t string) []any {
	if hierarchy, exists := u.hierarchy[t]; exists {
		return hierarchy
	}
	tenant, exists := u.GetTenant(t)
	if !exists {
		return nil
	}
	hierarchy := tenant.GetDescendants()
	u.hierarchy[t] = utils.Compact(hierarchy)
	return hierarchy
}

func (u *RoleManager) TotalTenants() int {
	return u.tenants.Size()
}

func (u *RoleManager) TotalPrincipals() int {
	return u.principals.Size()
}

func (u *RoleManager) AsString() string {
	data, err := json.Marshal(u.trie.Data())
	if err != nil {
		return ""
	}
	return utils.FromByte(data)
}

type Summary struct {
	Tenants         int `json:"tenants"`
	Principals      int `json:"principals"`
	Namespaces      int `json:"namespaces"`
	Scopes          int `json:"scopes"`
	Roles           int `json:"roles"`
	AttributeGroups int `json:"attribute_groups"`
	Attributes      int `json:"attributes"`
}

func (u *RoleManager) Summary() Summary {
	return Summary{
		Tenants:         u.TotalTenants(),
		Namespaces:      u.TotalNamespaces(),
		Scopes:          u.TotalScopes(),
		Principals:      u.TotalPrincipals(),
		Roles:           u.TotalRoles(),
		AttributeGroups: u.TotalAttributeGroups(),
		Attributes:      u.TotalAttributes(),
	}
}

func (u *RoleManager) SummaryMap() map[string]any {
	return map[string]any{
		"tenants":          u.TotalTenants(),
		"namespaces":       u.TotalNamespaces(),
		"scopes":           u.TotalScopes(),
		"principals":       u.TotalPrincipals(),
		"roles":            u.TotalRoles(),
		"attribute_groups": u.TotalAttributeGroups(),
		"attributes":       u.TotalAttributes(),
	}
}

func (u *RoleManager) String() string {
	summary := u.Summary()
	bt, _ := json.Marshal(summary)
	return utils.ToString(bt)
}
