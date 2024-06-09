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
	return u.SearchFuncWrapper(Data{Principal: principalID}, filterTenantsByPrincipal, func(d *Data) any { return d.Tenant })
}

func (u *RoleManager) GetTenants(principalID any) (data []*Data) {
	results := u.search(Data{Principal: principalID}, filterTenantsByPrincipal)
	return results
}

func (u *RoleManager) GetDescendantTenant(desc any) *Data {
	return u.trie.First(&Data{Tenant: desc})
}

func (u *RoleManager) GetImplicitTenants(principalID string) map[string]struct{} {
	tenantPrincipal := u.search(Data{Principal: principalID}, filterTenantsByPrincipal)
	existingTenant := make(map[string]struct{}, 0)
	for _, rs := range tenantPrincipal {
		tenantID := rs.Tenant.(string)
		if _, alreadyProcessed := existingTenant[tenantID]; alreadyProcessed {
			continue
		}
		existingTenant[tenantID] = struct{}{}
		if canManage, ok := rs.ManageDescendants.(bool); ok && canManage {
			for _, desc := range u.TenantChildren(tenantID) {
				if desc != nil {
					existingTenant[desc.(string)] = struct{}{}
				}
			}
		}
	}
	return existingTenant
}

func (u *RoleManager) GetScopesByPrincipal(principalID any) (data []*Data) {
	results := u.search(Data{Principal: principalID}, filterScopeByPrincipal)
	return results
}

func (u *RoleManager) GetRolesByTenant(tenantID any) (data []*Data) {
	results := u.search(Data{Tenant: tenantID}, filterRoleByTenant)
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
	results := u.search(Data{Tenant: tenantID, Principal: principalID}, filterNamespaceForPrincipalByTenant)
	return results
}

func (u *RoleManager) GetNamespacesByTenant(tenantID any) (data []*Data) {
	results := u.search(Data{Tenant: tenantID}, filterNamespaceByTenant)
	return results
}

func (u *RoleManager) GetScopesByTenant(tenantID any) (data []*Data) {
	results := u.search(Data{Tenant: tenantID}, filterScopeByTenant)
	return results
}

func (u *RoleManager) GetScopesForPrincipalByTenant(principalID, tenantID any) (data []*Data) {
	results := u.search(Data{Tenant: tenantID, Principal: principalID}, filterScopeForPrincipalByTenant)
	return results
}

func (u *RoleManager) GetScopeForPrincipalByNamespace(principalID, namespaceID any) (data []*Data) {
	tenants := u.GetTenantsByPrincipal(principalID)
	for _, tenant := range tenants {
		results := u.search(Data{Principal: principalID, Tenant: tenant, Namespace: namespaceID}, filterScopeForPrincipalByTenantAndNamespace)
		data = append(data, results...)
	}
	return data
}

func (u *RoleManager) GetScopesForPrincipalByTenantAndNamespace(principalID, tenantID, namespaceID any) (data []*Data) {
	return u.search(Data{Principal: principalID, Tenant: tenantID, Namespace: namespaceID}, filterScopeForPrincipalByTenantAndNamespace)
}

func (u *RoleManager) GetRolesForPrincipalByTenantNamespaceAndScope(principalID, tenantID, namespaceID, scope any) (data []*Data) {
	return u.search(Data{Principal: principalID, Tenant: tenantID, Namespace: namespaceID, Scope: scope}, filterRoleForPrincipalByTenantNamespaceAndScope)
}

func (u *RoleManager) GetRolesForPrincipalByTenantAndNamespace(principalID, tenantID, namespaceID any) (data []*Data) {
	return u.search(Data{Principal: principalID, Tenant: tenantID, Namespace: namespaceID}, filterRoleForPrincipalByTenantAndNamespace)
}

func (u *RoleManager) GetRolesForPrincipalByTenantAndScope(principalID, tenantID, scopeID any) (data []*Data) {
	return u.search(Data{Principal: principalID, Tenant: tenantID, Scope: scopeID}, filterRoleForPrincipalByTenantAndScope)
}

func (u *RoleManager) GetNamespaceByTenant(tenantID any) (data []*Data) {
	return u.search(Data{Tenant: tenantID}, filterNamespaceByTenant)
}

func (u *RoleManager) GetNamespaceForPrincipalByTenant(principalID, tenantID any) (data []*Data) {
	return u.search(Data{Tenant: tenantID, Principal: principalID}, filterNamespaceForPrincipalByTenant)
}
