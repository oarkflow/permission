package permission

import (
	"github.com/oarkflow/permission/utils"
)

// SearchFuncWrapper simplifies the search and data extraction process.
func (u *RoleManager) SearchFuncWrapper(filter Data, filterFunc func(*Data, *Data) bool, extractFunc func(*Data) any) (data []any) {
	results := u.search(filter, filterFunc)
	for _, result := range results {
		data = append(data, extractFunc(result))
	}
	return utils.Compact(data)
}

func (u *RoleManager) search(filter Data, filterFunc func(*Data, *Data) bool) []*Data {
	return u.trie.SearchFunc(&filter, filterFunc)
}

func (u *RoleManager) GetTenantsByPrincipal(principalID any) (data []any) {
	return u.SearchFuncWrapper(Data{PrincipalID: principalID}, filterTenantsByPrincipal, func(d *Data) any { return d.TenantID })
}

func (u *RoleManager) GetTenants(principalID any) (data []*Data) {
	results := u.search(Data{PrincipalID: principalID}, filterTenantsByPrincipal)
	return results
}

func (u *RoleManager) GetDescendantTenant(desc any) *Data {
	return u.trie.First(&Data{TenantID: desc})
}

func (u *RoleManager) GetImplicitTenants(principalID any) (data []*Data) {
	results := u.search(Data{PrincipalID: principalID}, filterTenantsByPrincipal)
	existingTenant := make(map[string]*Data)

	for _, rs := range results {
		tenantID, ok := rs.TenantID.(string)
		if !ok {
			continue
		}

		if _, alreadyProcessed := existingTenant[tenantID]; alreadyProcessed {
			continue
		}

		existingTenant[tenantID] = rs

		if canManage, ok := rs.CanManageDescendants.(bool); ok && canManage {
			if tenant, exists := u.tenants.Get(tenantID); exists {
				for _, desc := range tenant.GetDescendants() {
					if d := u.GetDescendantTenant(desc); d != nil {
						descendantID, ok := d.TenantID.(string)
						if ok {
							existingTenant[descendantID] = d
						}
					}
				}
			}
		}
	}

	for _, d := range existingTenant {
		data = append(data, d)
	}
	return data
}

func (u *RoleManager) GetScopesByPrincipal(principalID any) (data []*Data) {
	results := u.search(Data{PrincipalID: principalID}, filterScopeByPrincipal)
	return results
}

func (u *RoleManager) GetRolesByTenant(tenantID any) (data []*Data) {
	results := u.search(Data{TenantID: tenantID}, filterRoleByTenant)
	return results
}

func (u *RoleManager) GetNamespacesByPrincipal(principalID any) (data []*Data) {
	tenants := u.GetTenantsByPrincipal(principalID)
	for _, tenant := range tenants {
		data = append(data, u.GetNamespacesForPrincipalByTenant(principalID, tenant)...)
	}
	return data
}

func (u *RoleManager) GetNamespacesForPrincipalByTenant(principalID, tenantID any) (data []*Data) {
	results := u.search(Data{TenantID: tenantID, PrincipalID: principalID}, filterNamespaceForPrincipalByTenant)
	return results
}

func (u *RoleManager) GetNamespacesByTenant(tenantID any) (data []*Data) {
	results := u.search(Data{TenantID: tenantID}, filterNamespaceByTenant)
	return results
}

func (u *RoleManager) GetScopesByTenant(tenantID any) (data []*Data) {
	results := u.search(Data{TenantID: tenantID}, filterScopeByTenant)
	return results
}

func (u *RoleManager) GetScopesForPrincipalByTenant(principalID, tenantID any) (data []*Data) {
	results := u.search(Data{TenantID: tenantID, PrincipalID: principalID}, filterScopeForPrincipalByTenant)
	return results
}

func (u *RoleManager) GetScopeForPrincipalByNamespace(principalID, namespaceID any) (data []*Data) {
	tenants := u.GetTenantsByPrincipal(principalID)
	for _, tenant := range tenants {
		results := u.search(Data{PrincipalID: principalID, TenantID: tenant, NamespaceID: namespaceID}, filterScopeForPrincipalByTenantAndNamespace)
		data = append(data, results...)
	}
	return data
}

func (u *RoleManager) GetScopesForPrincipalByTenantAndNamespace(principalID, tenantID, namespaceID any) (data []*Data) {
	return u.search(Data{PrincipalID: principalID, TenantID: tenantID, NamespaceID: namespaceID}, filterScopeForPrincipalByTenantAndNamespace)
}

func (u *RoleManager) GetRolesForPrincipalByTenantNamespaceAndScope(principalID, tenantID, namespaceID, scope any) (data []*Data) {
	return u.search(Data{PrincipalID: principalID, TenantID: tenantID, NamespaceID: namespaceID, ScopeID: scope}, filterRoleForPrincipalByTenantNamespaceAndScope)
}

func (u *RoleManager) GetRolesForPrincipalByTenantAndNamespace(principalID, tenantID, namespaceID any) (data []*Data) {
	return u.search(Data{PrincipalID: principalID, TenantID: tenantID, NamespaceID: namespaceID}, filterRoleForPrincipalByTenantAndNamespace)
}

func (u *RoleManager) GetRolesForPrincipalByTenantAndScope(principalID, tenantID, scopeID any) (data []*Data) {
	return u.search(Data{PrincipalID: principalID, TenantID: tenantID, ScopeID: scopeID}, filterRoleForPrincipalByTenantAndScope)
}

func (u *RoleManager) GetNamespaceByTenant(tenantID any) (data []*Data) {
	return u.search(Data{TenantID: tenantID}, filterNamespaceByTenant)
}

func (u *RoleManager) GetNamespaceForPrincipalByTenant(principalID, tenantID any) (data []*Data) {
	return u.search(Data{TenantID: tenantID, PrincipalID: principalID}, filterNamespaceForPrincipalByTenant)
}
