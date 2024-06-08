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

// SearchFuncWrapper simplifies the search and data extraction process.
func (u *RoleManager) SearchFuncWrapper(filter trie.Data, filterFunc func(*trie.Data, *trie.Data) bool, extractFunc func(*trie.Data) any) (data []any) {
	results := u.trie.SearchFunc(filter, filterFunc)
	for _, result := range results {
		data = append(data, extractFunc(result))
	}
	return utils.Compact(data)
}

func (u *RoleManager) GetTenantsByPrincipal(principalID any) (data []any) {
	return u.SearchFuncWrapper(trie.Data{PrincipalID: principalID}, filterTenantsByPrincipal, func(d *trie.Data) any { return d.TenantID })
}

func (u *RoleManager) GetTenants(principalID any) (data []*trie.Data) {
	results := u.trie.SearchFunc(trie.Data{PrincipalID: principalID}, filterTenantsByPrincipal)
	return results
}

func (u *RoleManager) GetDescendentTenant(desc any) *trie.Data {
	return u.trie.First(trie.Data{TenantID: desc})
}

func (u *RoleManager) GetImplicitTenants(principalID any) (data []*trie.Data) {
	existingTenant := make(map[string]*trie.Data)
	results := u.trie.SearchFunc(trie.Data{PrincipalID: principalID}, filterTenantsByPrincipal)
	for _, rs := range results {
		tenantID := rs.TenantID.(string)
		if rs.CanManageDescendants != nil && rs.CanManageDescendants.(bool) {
			if _, ok := existingTenant[tenantID]; !ok {
				existingTenant[tenantID] = rs
				tenant, exists := u.tenants.Get(tenantID)
				if exists {
					for _, desc := range tenant.GetDescendants() {
						d := u.GetDescendentTenant(desc)
						if d != nil {
							existingTenant[d.TenantID.(string)] = d
						}
					}
				}
			}
		} else {
			existingTenant[tenantID] = rs
		}
	}
	for _, d := range existingTenant {
		data = append(data, d)
	}
	return data
}

func (u *RoleManager) GetScopesByPrincipal(principalID any) (data []*trie.Data) {
	results := u.trie.SearchFunc(trie.Data{PrincipalID: principalID}, filterScopeByPrincipal)
	return results
}

func (u *RoleManager) GetRolesByTenant(tenantID any) (data []*trie.Data) {
	results := u.trie.SearchFunc(trie.Data{TenantID: tenantID}, filterRoleByTenant)
	return results
}

func (u *RoleManager) GetNamespacesByPrincipal(principalID any) (data []*trie.Data) {
	tenants := u.GetTenantsByPrincipal(principalID)
	for _, tenant := range tenants {
		data = append(data, u.GetNamespacesForPrincipalByTenant(principalID, tenant)...)
	}
	return data
}

func (u *RoleManager) GetNamespacesForPrincipalByTenant(principalID, tenantID any) (data []*trie.Data) {
	if !utils.Contains(u.GetTenantsByPrincipal(principalID), tenantID) {
		return nil
	}
	results := u.trie.SearchFunc(trie.Data{TenantID: tenantID, PrincipalID: principalID}, filterNamespaceForPrincipalByTenant)
	return results
}

func (u *RoleManager) GetNamespacesByTenant(tenantID any) (data []*trie.Data) {
	results := u.trie.SearchFunc(trie.Data{TenantID: tenantID}, filterNamespaceByTenant)
	return results
}

func (u *RoleManager) GetScopesByTenant(tenantID any) (data []*trie.Data) {
	results := u.trie.SearchFunc(trie.Data{TenantID: tenantID}, filterScopeByTenant)
	return results
}

func (u *RoleManager) GetScopesForPrincipalByTenant(principalID, tenantID any) (data []*trie.Data) {
	if !utils.Contains(u.GetTenantsByPrincipal(principalID), tenantID) {
		return nil
	}
	results := u.trie.SearchFunc(trie.Data{TenantID: tenantID, PrincipalID: principalID}, filterScopeForPrincipalByTenant)
	return results
}

func (u *RoleManager) GetScopeForPrincipalByNamespace(principalID, namespaceID any) (data []*trie.Data) {
	tenants := u.GetTenantsByPrincipal(principalID)
	for _, tenant := range tenants {
		results := u.trie.SearchFunc(trie.Data{PrincipalID: principalID, TenantID: tenant, NamespaceID: namespaceID}, filterScopeForPrincipalByTenantAndNamespace)
		data = append(data, results...)
	}
	return data
}

func (u *RoleManager) GetScopesForPrincipalByTenantAndNamespace(principalID, tenantID, namespaceID any) (data []*trie.Data) {
	if !utils.Contains(u.GetTenantsByPrincipal(principalID), tenantID) {
		return nil
	}
	results := u.trie.SearchFunc(trie.Data{PrincipalID: principalID, TenantID: tenantID, NamespaceID: namespaceID}, filterScopeForPrincipalByTenantAndNamespace)
	return results
}

func (u *RoleManager) GetRolesForPrincipalByTenantNamespaceAndScope(principalID, tenantID, namespaceID, scope any) (data []*trie.Data) {
	if !utils.Contains(u.GetTenantsByPrincipal(principalID), tenantID) {
		return nil
	}
	results := u.trie.SearchFunc(trie.Data{PrincipalID: principalID, TenantID: tenantID, NamespaceID: namespaceID, ScopeID: scope}, filterRoleForPrincipalByTenantNamespaceAndScope)
	return results
}

func (u *RoleManager) GetRolesForPrincipalByTenantAndNamespace(principalID, tenantID, namespaceID any) (data []*trie.Data) {
	if !utils.Contains(u.GetTenantsByPrincipal(principalID), tenantID) {
		return nil
	}
	results := u.trie.SearchFunc(trie.Data{PrincipalID: principalID, TenantID: tenantID, NamespaceID: namespaceID}, filterRoleForPrincipalByTenantAndNamespace)
	return results
}

func (u *RoleManager) GetRolesForPrincipalByTenantAndScope(principalID, tenantID, scopeID any) (data []*trie.Data) {
	if !utils.Contains(u.GetTenantsByPrincipal(principalID), tenantID) {
		return nil
	}
	results := u.trie.SearchFunc(trie.Data{PrincipalID: principalID, TenantID: tenantID, ScopeID: scopeID}, filterRoleForPrincipalByTenantAndScope)
	return results
}

func (u *RoleManager) GetNamespaceByTenant(tenantID any) (data []*trie.Data) {
	results := u.trie.SearchFunc(trie.Data{TenantID: tenantID}, filterNamespaceByTenant)
	return results
}

func (u *RoleManager) GetNamespaceForPrincipalByTenant(principalID, tenantID any) (data []*trie.Data) {
	if !utils.Contains(u.GetTenantsByPrincipal(principalID), tenantID) {
		return nil
	}
	results := u.trie.SearchFunc(trie.Data{TenantID: tenantID, PrincipalID: principalID}, filterNamespaceForPrincipalByTenant)
	return results
}

func (u *RoleManager) Authorize(principalID string, options ...func(*Option)) bool {
	if _, exists := u.GetPrincipal(principalID); !exists {
		return false
	}

	userRoles := u.GetImplicitTenants(principalID)
	if len(userRoles) == 0 {
		return false
	}
	svr := &Option{}
	for _, o := range options {
		o(svr)
	}

	if !u.validateResources(svr) {
		return false
	}

	noActivity := svr.activityGroup == nil && svr.activity == nil
	tFlagProvided := svr.tenant != nil && svr.namespace == nil && svr.scope == nil
	tnFlagProvided := svr.tenant != nil && svr.namespace != nil && svr.scope == nil
	tsFlagProvided := svr.tenant != nil && svr.namespace == nil && svr.scope != nil
	tnsFlagProvided := svr.tenant != nil && svr.namespace != nil && svr.scope != nil
	nsFlagProvided := svr.tenant == nil && svr.namespace != nil && svr.scope != nil
	result := false
	if noActivity {
		result = u.checkNoActivity(principalID, svr, tFlagProvided, tnFlagProvided, tsFlagProvided, tnsFlagProvided, nsFlagProvided)
	} else {
		result = u.checkActivity(principalID, svr, tFlagProvided, tnFlagProvided, tsFlagProvided, tnsFlagProvided, nsFlagProvided)
	}
	if result {
		return result
	}
	for _, tenant := range userRoles {
		if svr.tenant == tenant.TenantID {
			continue
		}
		svr.tenant = tenant.TenantID
		if noActivity {
			result = u.checkNoActivity(principalID, svr, tFlagProvided, tnFlagProvided, tsFlagProvided, tnsFlagProvided, nsFlagProvided)
		} else {
			result = u.checkActivity(principalID, svr, tFlagProvided, tnFlagProvided, tsFlagProvided, tnsFlagProvided, nsFlagProvided)
		}
		if result {
			return result
		}
	}
	return false
}

func (u *RoleManager) validateResources(svr *Option) bool {
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
	return true
}

func (u *RoleManager) checkNoActivity(principalID string, svr *Option, tFlagProvided, tnFlagProvided, tsFlagProvided, tnsFlagProvided, nsFlagProvided bool) bool {
	if tFlagProvided {
		return utils.Contains(u.GetTenantsByPrincipal(principalID), svr.tenant)
	}
	if tnFlagProvided {
		return utils.Contains(getNamespaceIDs(u.GetNamespaceForPrincipalByTenant(principalID, svr.tenant)), svr.namespace)
	}
	if tsFlagProvided {
		return utils.Contains(getScopeIDs(u.GetScopesForPrincipalByTenant(principalID, svr.tenant)), svr.scope)
	}
	if nsFlagProvided {
		return utils.Contains(getScopeIDs(u.GetScopeForPrincipalByNamespace(principalID, svr.namespace)), svr.scope)
	}
	if tnsFlagProvided {
		return utils.Contains(getScopeIDs(u.GetScopesForPrincipalByTenantAndNamespace(principalID, svr.tenant, svr.namespace)), svr.scope)
	}
	return false
}

func (u *RoleManager) checkActivity(principalID string, svr *Option, tFlagProvided, tnFlagProvided, tsFlagProvided, tnsFlagProvided, nsFlagProvided bool) bool {
	var allowedRoles, roles []string
	if tFlagProvided {
		roles, allowedRoles = u.collectRoles(principalID, svr.tenant)
	}
	if tnFlagProvided {
		roles, allowedRoles = u.collectRolesByTenantAndNamespace(principalID, svr.tenant, svr.namespace)
	}
	if tsFlagProvided {
		roles, allowedRoles = u.collectRolesByTenantAndScope(principalID, svr.tenant, svr.scope)
	}
	if nsFlagProvided {
		roles, allowedRoles = u.collectRolesByNamespaceAndScope(principalID, svr.namespace, svr.scope)
	}
	if tnsFlagProvided {
		roles, allowedRoles = u.collectRolesByTenantNamespaceAndScope(principalID, svr.tenant, svr.namespace, svr.scope)
	}

	if len(roles) == 0 {
		return false
	}

	for _, role := range slices.Compact(roles) {
		if r, exists := u.roles.Get(role); exists && r.Has(svr.activityGroup.(string), svr.activity.(string), slices.Compact(allowedRoles)...) {
			return true
		}
	}
	return false
}

func (u *RoleManager) collectRoles(principalID string, tenant any) (roles, allowedRoles []string) {
	for _, d := range u.GetRolesByTenant(tenant) {
		if d.PrincipalID == principalID {
			roles = append(roles, d.RoleID.(string))
		}
		allowedRoles = append(allowedRoles, d.RoleID.(string))
	}
	return
}

func (u *RoleManager) collectRolesByTenantAndNamespace(principalID string, tenant, namespace any) (roles, allowedRoles []string) {
	for _, d := range u.GetRolesByTenant(tenant) {
		allowedRoles = append(allowedRoles, d.RoleID.(string))
	}
	for _, d := range u.GetRolesForPrincipalByTenantAndNamespace(principalID, tenant, namespace) {
		if d.NamespaceID == nil || d.NamespaceID == namespace {
			roles = append(roles, d.RoleID.(string))
		}
	}
	return
}

func (u *RoleManager) collectRolesByTenantAndScope(principalID string, tenant, scope any) (roles, allowedRoles []string) {
	for _, d := range u.GetRolesByTenant(tenant) {
		allowedRoles = append(allowedRoles, d.RoleID.(string))
	}
	for _, d := range u.GetRolesForPrincipalByTenantAndScope(principalID, tenant, scope) {
		if d.ScopeID == nil || d.ScopeID == scope {
			roles = append(roles, d.RoleID.(string))
		}
	}
	return
}

func (u *RoleManager) collectRolesByNamespaceAndScope(principalID string, namespace, scope any) (roles, allowedRoles []string) {
	for _, t := range u.GetTenants(principalID) {
		for _, d := range u.GetRolesByTenant(t.TenantID) {
			allowedRoles = append(allowedRoles, d.RoleID.(string))
		}
		for _, d := range u.GetRolesForPrincipalByTenantNamespaceAndScope(principalID, t.TenantID, namespace, scope) {
			if (d.NamespaceID == nil || d.NamespaceID == namespace) && (d.ScopeID == nil || d.ScopeID == scope) {
				roles = append(roles, d.RoleID.(string))
			}
		}
	}
	return
}

func (u *RoleManager) collectRolesByTenantNamespaceAndScope(principalID string, tenant, namespace, scope any) (roles, allowedRoles []string) {
	for _, d := range u.GetRolesByTenant(tenant) {
		allowedRoles = append(allowedRoles, d.RoleID.(string))
	}
	for _, d := range u.GetRolesForPrincipalByTenantNamespaceAndScope(principalID, tenant, namespace, scope) {
		if (d.NamespaceID == nil || d.NamespaceID == namespace) && (d.ScopeID == nil || d.ScopeID == scope) {
			roles = append(roles, d.RoleID.(string))
		}
	}
	return
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
