package v2

import (
	"github.com/oarkflow/permission/trie"
	"github.com/oarkflow/permission/utils"
)

func (u *RoleManager) GetImplicitTenantsByPrincipal(principalID any) (data []any) {
	tenants := u.trie.SearchFunc(trie.Data{PrincipalID: principalID}, filterTenantsByPrincipal)
	for _, tenant := range tenants {
		data = append(data, tenant.TenantID)
		if tenant.CanManageDescendants != nil && tenant.CanManageDescendants.(bool) {
			if ten, ok := u.tenants.Get(tenant.TenantID.(string)); ok {
				data = append(data, ten.GetDescendants()...)
			}
		}
	}
	data = utils.Compact(data)
	return
}

func (u *RoleManager) GetImplicitScopesByPrincipal(principalID any) (data []any) {
	rss := u.trie.SearchFunc(trie.Data{PrincipalID: principalID}, filterScopeByPrincipal)
	for _, rs := range rss {
		data = append(data, rs.ScopeID)
		if rs.CanManageDescendants != nil && rs.CanManageDescendants.(bool) {
			if ten, ok := u.tenants.Get(rs.TenantID.(string)); ok {
				ten.descendants.ForEach(func(id string, _ *Tenant) bool {
					data = append(data, u.GetScopesForPrincipalByTenant(principalID, id)...)
					return true
				})
			}
		}
	}
	data = utils.Compact(data)
	return
}

func (u *RoleManager) GetImplicitScopesForPrincipalByTenantAndNamespace(principalID, tenantID, namespaceID any) (data []any) {
	rss := u.trie.SearchFunc(trie.Data{PrincipalID: principalID, TenantID: tenantID, NamespaceID: namespaceID}, filterScopeForPrincipalByTenantAndNamespace)
	for _, rs := range rss {
		data = append(data, rs.ScopeID)
		if rs.CanManageDescendants != nil && rs.CanManageDescendants.(bool) {
			if ten, ok := u.tenants.Get(rs.TenantID.(string)); ok {
				ten.descendants.ForEach(func(id string, _ *Tenant) bool {
					data = append(data, u.GetImplicitScopesForPrincipalByTenantAndNamespace(principalID, id, namespaceID)...)
					return true
				})
			}
		}
	}
	data = utils.Compact(data)
	return
}

func (u *RoleManager) GetImplicitNamespacesByPrincipal(principalID any) (data []any) {
	tenants := u.GetImplicitTenantsByPrincipal(principalID)
	if len(tenants) == 0 {
		return
	}
	for _, tenant := range tenants {
		data = append(data, u.GetImplicitNamespaceForPrincipalByTenant(principalID, tenant)...)
	}
	data = utils.Compact(data)
	return
}

func (u *RoleManager) GetImplicitNamespaceByTenant(tenantID any) (data []any) {
	rss := u.trie.SearchFunc(trie.Data{TenantID: tenantID}, filterNamespaceByTenant)
	for _, rs := range rss {
		data = append(data, rs.NamespaceID)
		if rs.CanManageDescendants != nil && rs.CanManageDescendants.(bool) {
			if ten, ok := u.tenants.Get(tenantID.(string)); ok {
				ten.descendants.ForEach(func(id string, _ *Tenant) bool {
					data = append(data, u.GetImplicitNamespaceByTenant(id)...)
					return true
				})
			}
		}
	}
	data = utils.Compact(data)
	return
}

func (u *RoleManager) GetImplicitNamespaceForPrincipalByTenant(principalID, tenantID any) (data []any) {
	rss := u.trie.SearchFunc(trie.Data{TenantID: tenantID, PrincipalID: principalID}, filterNamespaceForPrincipalByTenant)
	for _, rs := range rss {
		data = append(data, rs.NamespaceID)
		if rs.CanManageDescendants != nil && rs.CanManageDescendants.(bool) {
			if ten, ok := u.tenants.Get(tenantID.(string)); ok {
				ten.descendants.ForEach(func(id string, _ *Tenant) bool {
					data = append(data, u.GetImplicitNamespaceForPrincipalByTenant(principalID, id)...)
					return true
				})
			}
		}
	}
	data = utils.Compact(data)
	return
}

func (u *RoleManager) GetImplicitScopesForPrincipalByTenant(principalID, tenantID any) (data []any) {
	rss := u.trie.SearchFunc(trie.Data{TenantID: tenantID, PrincipalID: principalID}, filterScopeForPrincipalByTenant)
	for _, rs := range rss {
		data = append(data, rs.ScopeID)
		if rs.CanManageDescendants != nil && rs.CanManageDescendants.(bool) {
			if ten, ok := u.tenants.Get(tenantID.(string)); ok {
				ten.descendants.ForEach(func(id string, _ *Tenant) bool {
					data = append(data, u.GetImplicitScopesForPrincipalByTenant(principalID, id)...)
					return true
				})
			}
		}
	}
	data = utils.Compact(data)
	return
}
