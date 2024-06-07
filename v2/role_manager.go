package v2

import (
	"errors"
	"fmt"
	"slices"

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

func (u *RoleManager) GetTenants(principalID any) (data []*trie.Data) {
	rss := u.trie.SearchFunc(trie.Data{PrincipalID: principalID}, filterTenantsByPrincipal)
	for _, rs := range rss {
		data = append(data, rs)
	}
	return
}

func (u *RoleManager) GetScopesByPrincipal(principalID any) (data []*trie.Data) {
	rss := u.trie.SearchFunc(trie.Data{PrincipalID: principalID}, filterScopeByPrincipal)
	for _, rs := range rss {
		data = append(data, rs)
	}
	return
}

func (u *RoleManager) GetRolesByTenant(tenantID any) (data []*trie.Data) {
	rss := u.trie.SearchFunc(trie.Data{TenantID: tenantID}, filterRoleByTenant)
	for _, rs := range rss {
		data = append(data, rs)
	}
	return
}

func (u *RoleManager) GetNamespacesByPrincipal(principalID any) (data []*trie.Data) {
	tenants := u.GetTenantsByPrincipal(principalID)
	if len(tenants) == 0 {
		return
	}
	for _, tenant := range tenants {
		data = append(data, u.GetNamespacesForPrincipalByTenant(principalID, tenant)...)
	}
	return
}

func (u *RoleManager) GetNamespacesForPrincipalByTenant(principalID, tenantID any) (data []*trie.Data) {
	tenants := u.GetTenantsByPrincipal(principalID)
	if !utils.Contains(tenants, tenantID) {
		return
	}
	rss := u.trie.SearchFunc(trie.Data{TenantID: tenantID, PrincipalID: principalID}, filterNamespaceForPrincipalByTenant)
	for _, rs := range rss {
		data = append(data, rs)
	}
	return
}

func (u *RoleManager) GetNamespacesByTenant(tenantID any) (data []*trie.Data) {
	rss := u.trie.SearchFunc(trie.Data{TenantID: tenantID}, filterNamespaceByTenant)
	for _, rs := range rss {
		data = append(data, rs)
	}
	return
}

func (u *RoleManager) GetScopesByTenant(tenantID any) (data []*trie.Data) {
	rss := u.trie.SearchFunc(trie.Data{TenantID: tenantID}, filterScopeByTenant)
	for _, rs := range rss {
		data = append(data, rs)
	}
	return
}

func (u *RoleManager) GetScopesForPrincipalByTenant(principalID, tenantID any) (data []*trie.Data) {
	tenants := u.GetTenantsByPrincipal(principalID)
	if !utils.Contains(tenants, tenantID) {
		return
	}
	rss := u.trie.SearchFunc(trie.Data{TenantID: tenantID, PrincipalID: principalID}, filterScopeForPrincipalByTenant)
	for _, rs := range rss {
		data = append(data, rs)
	}
	return
}

func (u *RoleManager) GetScopeForPrincipalByNamespace(principalID, namespaceID any) (data []*trie.Data) {
	tenants := u.GetTenantsByPrincipal(principalID)
	for _, tenant := range tenants {
		rss := u.trie.SearchFunc(trie.Data{PrincipalID: principalID, TenantID: tenant, NamespaceID: namespaceID}, filterScopeForPrincipalByTenantAndNamespace)
		for _, rs := range rss {
			data = append(data, rs)
		}
	}
	return
}

func (u *RoleManager) GetScopesForPrincipalByTenantAndNamespace(principalID, tenantID, namespaceID any) (data []*trie.Data) {
	tenants := u.GetTenantsByPrincipal(principalID)
	if !utils.Contains(tenants, tenantID) {
		return
	}
	rss := u.trie.SearchFunc(trie.Data{PrincipalID: principalID, TenantID: tenantID, NamespaceID: namespaceID}, filterScopeForPrincipalByTenantAndNamespace)
	for _, rs := range rss {
		data = append(data, rs)
	}
	return
}

func (u *RoleManager) GetRolesForPrincipalByTenantNamespaceAndScope(principalID, tenantID, namespaceID, scope any) (data []*trie.Data) {
	tenants := u.GetTenantsByPrincipal(principalID)
	if !utils.Contains(tenants, tenantID) {
		return
	}
	rss := u.trie.SearchFunc(trie.Data{PrincipalID: principalID, TenantID: tenantID, NamespaceID: namespaceID, ScopeID: scope}, filterRoleForPrincipalByTenantNamespaceAndScope)
	for _, rs := range rss {
		data = append(data, rs)
	}
	return
}

func (u *RoleManager) GetRolesForPrincipalByTenantAndNamespace(principalID, tenantID, namespaceID any) (data []*trie.Data) {
	tenants := u.GetTenantsByPrincipal(principalID)
	if !utils.Contains(tenants, tenantID) {
		return

	}
	rss := u.trie.SearchFunc(trie.Data{PrincipalID: principalID, TenantID: tenantID, NamespaceID: namespaceID}, filterRoleForPrincipalByTenantAndNamespace)
	for _, rs := range rss {
		data = append(data, rs)
	}
	return
}

func (u *RoleManager) GetRolesForPrincipalByTenantAndScope(principalID, tenantID, scopeID any) (data []*trie.Data) {
	tenants := u.GetTenantsByPrincipal(principalID)
	if !utils.Contains(tenants, tenantID) {
		return

	}
	rss := u.trie.SearchFunc(trie.Data{PrincipalID: principalID, TenantID: tenantID, ScopeID: scopeID}, filterRoleForPrincipalByTenantAndScope)
	for _, rs := range rss {
		data = append(data, rs)
	}
	return
}

func (u *RoleManager) GetNamespaceByTenant(tenantID any) (data []*trie.Data) {
	rss := u.trie.SearchFunc(trie.Data{TenantID: tenantID}, filterNamespaceByTenant)
	for _, rs := range rss {
		data = append(data, rs)
	}
	return
}

func (u *RoleManager) GetNamespaceForPrincipalByTenant(principalID, tenantID any) (data []*trie.Data) {
	tenants := u.GetTenantsByPrincipal(principalID)
	if !utils.Contains(tenants, tenantID) {
		return
	}
	rss := u.trie.SearchFunc(trie.Data{TenantID: tenantID, PrincipalID: principalID}, filterNamespaceForPrincipalByTenant)
	for _, rs := range rss {
		data = append(data, rs)
	}
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
	noActivity := svr.activityGroup == nil && svr.activity == nil
	tFlagProvided := svr.tenant != nil && svr.namespace == nil && svr.scope == nil
	tnFlagProvided := svr.tenant != nil && svr.namespace != nil && svr.scope == nil
	tsFlagProvided := svr.tenant != nil && svr.namespace == nil && svr.scope != nil
	tnsFlagProvided := svr.tenant != nil && svr.namespace != nil && svr.scope != nil
	nsFlagProvided := svr.tenant == nil && svr.namespace != nil && svr.scope != nil
	if noActivity {
		if tFlagProvided {
			tenants := u.GetTenantsByPrincipal(principalID)
			return utils.Contains(tenants, svr.tenant)
		}
		if tnFlagProvided {
			rs := u.GetNamespaceForPrincipalByTenant(principalID, svr.tenant)
			return utils.Contains(getNamespaceIDs(rs), svr.namespace)
		}
		if tsFlagProvided {
			rs := u.GetScopesForPrincipalByTenant(principalID, svr.tenant)
			return utils.Contains(getScopeIDs(rs), svr.scope)
		}
		if nsFlagProvided {
			rs := u.GetScopeForPrincipalByNamespace(principalID, svr.namespace)
			return utils.Contains(getScopeIDs(rs), svr.scope)
		}
		if tnsFlagProvided {
			rs := u.GetScopesForPrincipalByTenantAndNamespace(principalID, svr.tenant, svr.namespace)
			return utils.Contains(getScopeIDs(rs), svr.scope)
		}
		return false
	}
	var allowedRoles, roles []string
	if tFlagProvided {
		for _, d := range u.GetRolesByTenant(svr.tenant) {
			if d.PrincipalID == principalID {
				roles = append(roles, d.RoleID.(string))
			}
			allowedRoles = append(allowedRoles, d.RoleID.(string))
		}
	}
	if tnFlagProvided {
		for _, d := range u.GetRolesByTenant(svr.tenant) {
			allowedRoles = append(allowedRoles, d.RoleID.(string))
		}
		for _, d := range u.GetRolesForPrincipalByTenantAndNamespace(principalID, svr.tenant, svr.namespace) {
			if !(d.NamespaceID != nil && svr.namespace != d.NamespaceID) {
				roles = append(roles, d.RoleID.(string))
			}
		}
	}
	if tsFlagProvided {
		for _, d := range u.GetRolesByTenant(svr.tenant) {
			allowedRoles = append(allowedRoles, d.RoleID.(string))
		}
		for _, d := range u.GetRolesForPrincipalByTenantAndScope(principalID, svr.tenant, svr.scope) {
			if !(d.ScopeID != nil && svr.scope != d.ScopeID) {
				roles = append(roles, d.RoleID.(string))
			}
		}
	}
	if nsFlagProvided {
		for _, t := range u.GetTenants(principalID) {
			for _, d := range u.GetRolesByTenant(t.TenantID) {
				allowedRoles = append(allowedRoles, d.RoleID.(string))
			}
			for _, d := range u.GetRolesForPrincipalByTenantNamespaceAndScope(principalID, t.TenantID, svr.namespace, svr.scope) {
				if !((d.NamespaceID != nil && svr.namespace != d.NamespaceID) || (d.ScopeID != nil && svr.scope != d.ScopeID)) {
					roles = append(roles, d.RoleID.(string))
				}
			}
		}
	}
	if tnsFlagProvided {
		for _, d := range u.GetRolesByTenant(svr.tenant) {
			allowedRoles = append(allowedRoles, d.RoleID.(string))
		}
		for _, d := range u.GetRolesForPrincipalByTenantNamespaceAndScope(principalID, svr.tenant, svr.namespace, svr.scope) {
			if !((d.NamespaceID != nil && svr.namespace != d.NamespaceID) || (d.ScopeID != nil && svr.scope != d.ScopeID)) {
				roles = append(roles, d.RoleID.(string))
			}
		}
	}
	if len(roles) == 0 {
		return false
	}
	roles = slices.Compact(roles)
	allowedRoles = slices.Compact(allowedRoles)
	for _, r := range roles {
		if role, ex := u.roles.Get(r); ex {
			if role.Has(svr.activityGroup.(string), svr.activity.(string), allowedRoles...) {
				return true
			}
		}
	}
	return false
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
