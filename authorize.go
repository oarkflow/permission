package permission

import (
	"slices"

	"github.com/oarkflow/permission/utils"
)

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
	if u.authorize(noActivity, principalID, svr, tFlagProvided, tnFlagProvided, tsFlagProvided, tnsFlagProvided, nsFlagProvided) {
		return true
	}
	for _, tenant := range userRoles {
		if svr.tenant == tenant.Tenant && svr.tenant != nil {
			continue
		}
		svr.tenant = tenant.Tenant
		if u.authorize(noActivity, principalID, svr, tFlagProvided, tnFlagProvided, tsFlagProvided, tnsFlagProvided, nsFlagProvided) {
			return true
		}
	}
	return false
}

func (u *RoleManager) authorize(noActivity bool, principalID string, svr *Option, tFlagProvided, tnFlagProvided, tsFlagProvided, tnsFlagProvided, nsFlagProvided bool) bool {
	if noActivity {
		return u.checkNoActivity(principalID, svr, tFlagProvided, tnFlagProvided, tsFlagProvided, tnsFlagProvided, nsFlagProvided)
	}
	return u.checkActivity(principalID, svr, tFlagProvided, tnFlagProvided, tsFlagProvided, tnsFlagProvided, nsFlagProvided)
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
		if d.Principal == principalID {
			roles = append(roles, d.Role.(string))
		}
		allowedRoles = append(allowedRoles, d.Role.(string))
	}
	return
}

func (u *RoleManager) collectRolesByTenantAndNamespace(principalID string, tenant, namespace any) (roles, allowedRoles []string) {
	for _, d := range u.GetRolesByTenant(tenant) {
		allowedRoles = append(allowedRoles, d.Role.(string))
	}
	for _, d := range u.GetRolesForPrincipalByTenantAndNamespace(principalID, tenant, namespace) {
		if d.Namespace == nil || d.Namespace == namespace {
			roles = append(roles, d.Role.(string))
		}
	}
	return
}

func (u *RoleManager) collectRolesByTenantAndScope(principalID string, tenant, scope any) (roles, allowedRoles []string) {
	for _, d := range u.GetRolesByTenant(tenant) {
		allowedRoles = append(allowedRoles, d.Role.(string))
	}
	for _, d := range u.GetRolesForPrincipalByTenantAndScope(principalID, tenant, scope) {
		if d.Scope == nil || d.Scope == scope {
			roles = append(roles, d.Role.(string))
		}
	}
	return
}

func (u *RoleManager) collectRolesByNamespaceAndScope(principalID string, namespace, scope any) (roles, allowedRoles []string) {
	for _, t := range u.GetTenants(principalID) {
		for _, d := range u.GetRolesByTenant(t.Tenant) {
			allowedRoles = append(allowedRoles, d.Role.(string))
		}
		for _, d := range u.GetRolesForPrincipalByTenantNamespaceAndScope(principalID, t.Tenant, namespace, scope) {
			if (d.Namespace == nil || d.Namespace == namespace) && (d.Scope == nil || d.Scope == scope) {
				roles = append(roles, d.Role.(string))
			}
		}
	}
	return
}

func (u *RoleManager) collectRolesByTenantNamespaceAndScope(principalID string, tenant, namespace, scope any) (roles, allowedRoles []string) {
	for _, d := range u.GetRolesByTenant(tenant) {
		allowedRoles = append(allowedRoles, d.Role.(string))
	}
	for _, d := range u.GetRolesForPrincipalByTenantNamespaceAndScope(principalID, tenant, namespace, scope) {
		if (d.Namespace == nil || d.Namespace == namespace) && (d.Scope == nil || d.Scope == scope) {
			roles = append(roles, d.Role.(string))
		}
	}
	return
}
