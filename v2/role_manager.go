package v2

import (
	"errors"
	"fmt"

	"github.com/oarkflow/maps"

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

func (u *RoleManager) GetTenantsByPrincipal(principalID any) (data []any) {
	rss := u.trie.SearchFunc(trie.Data{PrincipalID: principalID}, filterTenantsByPrincipal)
	for _, rs := range rss {
		data = append(data, rs.TenantID)
	}
	data = utils.Compact(data)
	return
}

func (u *RoleManager) GetScopesByPrincipal(principalID any) (data []any) {
	rss := u.trie.SearchFunc(trie.Data{PrincipalID: principalID}, filterScopeByPrincipal)
	for _, rs := range rss {
		data = append(data, rs.ScopeID)
	}
	data = utils.Compact(data)
	return
}

func (u *RoleManager) GetNamespacesByPrincipal(principalID any) (data []any) {
	tenants := u.GetTenantsByPrincipal(principalID)
	if len(tenants) == 0 {
		return
	}
	for _, tenant := range tenants {
		data = append(data, u.GetNamespacesForPrincipalByTenant(principalID, tenant)...)
	}
	data = utils.Compact(data)
	return
}

func (u *RoleManager) GetNamespacesByTenant(tenantID any) (data []any) {
	rss := u.trie.SearchFunc(trie.Data{TenantID: tenantID}, filterNamespaceByTenant)
	for _, rs := range rss {
		data = append(data, rs.NamespaceID)
	}
	data = utils.Compact(data)
	return
}

func (u *RoleManager) GetScopesByTenant(tenantID any) (data []any) {
	rss := u.trie.SearchFunc(trie.Data{TenantID: tenantID}, filterScopeByTenant)
	for _, rs := range rss {
		data = append(data, rs.ScopeID)
	}
	data = utils.Compact(data)
	return
}

func (u *RoleManager) GetScopesForPrincipalByTenant(principalID, tenantID any) (data []any) {
	rss := u.trie.SearchFunc(trie.Data{TenantID: tenantID, PrincipalID: principalID}, filterScopeForPrincipalByTenant)
	for _, rs := range rss {
		data = append(data, rs.ScopeID)
	}
	data = utils.Compact(data)
	return
}

func (u *RoleManager) GetNamespacesForPrincipalByTenant(principalID, tenantID any) (data []any) {
	rss := u.trie.SearchFunc(trie.Data{TenantID: tenantID, PrincipalID: principalID}, filterNamespaceForPrincipalByTenant)
	for _, rs := range rss {
		data = append(data, rs.NamespaceID)
	}
	data = utils.Compact(data)
	return
}

func (u *RoleManager) Authorize(principalID string, options ...func(*Option)) bool {
	if _, exists := u.GetPrincipal(principalID); !exists {
		return false
	}
	svr := &Option{}
	for _, o := range options {
		o(svr)
	}
	noActivity := svr.activityGroup == nil && svr.activity == nil
	tFlagProvided := svr.tenant != nil && svr.namespace == nil && svr.scope == nil
	tnFlagProvided := svr.tenant != nil && svr.namespace != nil && svr.scope == nil
	tsFlagProvided := svr.tenant != nil && svr.namespace == nil && svr.scope != nil
	tnsFlagProvided := svr.tenant != nil && svr.namespace != nil && svr.scope != nil
	if noActivity {
		if tFlagProvided {
			tenants := u.GetImplicitTenantsByPrincipal(principalID)
			return utils.Contains(tenants, svr.tenant)
		}
		if tnFlagProvided {
			nms := u.GetImplicitNamespaceForPrincipalByTenant(principalID, svr.tenant)
			return utils.Contains(nms, svr.namespace)
		}
		if tsFlagProvided {
			nms := u.GetImplicitScopesForPrincipalByTenant(principalID, svr.tenant)
			return utils.Contains(nms, svr.scope)
		}
		if tnsFlagProvided {
			nms := u.GetImplicitScopesForPrincipalByTenantAndNamespace(principalID, svr.tenant, svr.namespace)
			return utils.Contains(nms, svr.scope)
		}
	}

	/*fmt.Println("Tenants")
	data := u.trie.SearchFunc(trie.Data{PrincipalID: principalID}, func(f *trie.Data, n *trie.Data) bool {
		if f.PrincipalID == nil {
			return false
		}
		return n.PrincipalID == f.PrincipalID && n.TenantID != nil
	})
	for _, d := range data {
		fmt.Println(d)
	}
	fmt.Println("Principal Scopes")
	scopes := u.trie.SearchFunc(trie.Data{PrincipalID: principalID}, func(f *trie.Data, row *trie.Data) bool {
		if f.PrincipalID == nil {
			return false
		}
		return row.PrincipalID == f.PrincipalID && row.ScopeID != nil
	})
	for _, d := range scopes {
		fmt.Println(d)
	}
	fmt.Println("Tenant Scopes")
	tenantScopes := u.trie.SearchFunc(trie.Data{PrincipalID: principalID, TenantID: "TenantA"}, func(filter *trie.Data, row *trie.Data) bool {
		if filter.PrincipalID == nil || row.ScopeID == nil {
			return false
		}
		return (row.TenantID == filter.TenantID && row.PrincipalID == filter.PrincipalID) ||
			(row.TenantID == filter.TenantID && row.PrincipalID == nil)
	})
	for _, d := range tenantScopes {
		fmt.Println(d)
	}


	if svr.tenant != nil {
		if _, ok := u.tenants.Get(svr.tenant.(string)); !ok {
			return false
		}
	}
	if svr.namespace != nil {
		if _, ok := u.namespaces.Get(svr.namespace.(string)); !ok {
			return false
		}
	}

	if svr.scope != nil {
		if _, ok := u.scopes.Get(svr.scope.(string)); !ok {
			return false
		}
	}

	principalData := make(map[string]*trie.Data)
	tenants := u.GetImplicitTenantsForPrincipal(principalID)
	for _, tenant := range tenants {
		filter := trie.Data{TenantID: tenant}
		filteredData := u.trie.Search(filter)
		for _, p := range filteredData {
			if p.PrincipalID == nil || (p.PrincipalID != nil && p.PrincipalID.(string) == principalID) {
				principalData[trie.Key(p)] = p
			}
		}
	}
	*/
	return false
}

func (u *RoleManager) AddData(tenantID, namespaceID, scopeID, principalID, roleID, canManageDescendants any) {
	u.trie.Insert(trie.AddData(tenantID, namespaceID, scopeID, principalID, roleID, canManageDescendants))
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

func (u *RoleManager) AddPermissionsToRole(roleID, attributeGroupID string, attrs ...*Attribute) error {
	role, ok := u.roles.Get(roleID)
	if !ok {
		return errors.New("no role available")
	}
	attributeGroup, ok := u.attributeGroups.Get(attributeGroupID)
	if !ok {
		return errors.New("no attribute group available")
	}
	for _, attr := range attrs {
		if _, ok := attributeGroup.permissions.Get(attr.String()); !ok {
			return fmt.Errorf("attribute '%s' not associated to the group '%s'", attr.String(), attributeGroupID)
		}
	}
	return role.AddPermission(attributeGroupID, attrs...)
}
