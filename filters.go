package permission

import (
	"github.com/oarkflow/permission/utils"
)

type Data struct {
	Tenant            any
	Namespace         any
	Scope             any
	Principal         any
	Role              any
	ManageDescendants any
}

func FilterFunc(filter *Data, row *Data) bool {
	if !utils.IsNil(filter.Tenant) && !MatchTenant(row, filter) {
		return false
	}
	if !utils.IsNil(filter.Principal) && !MatchPrincipal(row, filter) {
		return false
	}
	if !utils.IsNil(filter.Role) && !MatchRole(row, filter) {
		return false
	}
	if !utils.IsNil(filter.Namespace) && !MatchNamespace(row, filter) {
		return false
	}
	if !utils.IsNil(filter.Scope) && !MatchScope(row, filter) {
		return false
	}
	if !utils.IsNil(filter.ManageDescendants) && filter.ManageDescendants != row.ManageDescendants {
		return false
	}
	return true
}

func filterTenantsByPrincipal(filter *Data, row *Data) bool {
	return (MatchPrincipal(row, filter)) && !utils.IsNil(row.Tenant)
}

func filterTenant(filter *Data, row *Data) bool {
	return (MatchTenant(row, filter)) && !utils.IsNil(row.Tenant)
}

func filterScopeByPrincipal(filter *Data, row *Data) bool {
	return (MatchPrincipal(row, filter)) && !utils.IsNil(row.Scope) && !utils.IsNil(row.Tenant)
}

func filterRoleByTenant(filter *Data, row *Data) bool {
	return MatchTenant(row, filter) && MatchRole(row, filter)
}

func filterNamespaceByTenant(filter *Data, row *Data) bool {
	return MatchTenant(row, filter) && !utils.IsNil(row.Namespace)
}

func filterScopeByTenant(filter *Data, row *Data) bool {
	return MatchTenant(row, filter) && !utils.IsNil(row.Scope)
}

func filterScopeByTenantAndNamespace(filter *Data, row *Data) bool {
	return MatchTenant(row, filter) && MatchNamespace(row, filter) && !utils.IsNil(row.Scope)
}

func filterPrincipalByTenantAndNamespace(filter *Data, row *Data) bool {
	return MatchTenant(row, filter) && MatchNamespace(row, filter) && MatchPrincipal(row, filter)
}

func filterScopeForPrincipalByTenant(filter *Data, row *Data) bool {
	if utils.IsNil(filter.Tenant) && utils.IsNil(filter.Principal) || utils.IsNil(row.Scope) {
		return false
	}
	return MatchTenant(row, filter) && (utils.IsNil(row.Principal) || MatchPrincipal(row, filter))
}

func filterScopeForPrincipalByNamespace(filter *Data, row *Data) bool {
	if utils.IsNil(filter.Namespace) && utils.IsNil(filter.Principal) || utils.IsNil(row.Scope) {
		return false
	}
	return !utils.IsNil(row.Tenant) && (utils.IsNil(row.Principal) || MatchPrincipal(row, filter))
}

func filterScopeForPrincipalByTenantAndNamespace(filter *Data, row *Data) bool {
	if utils.IsNil(filter.Tenant) && utils.IsNil(filter.Principal) && utils.IsNil(filter.Namespace) || utils.IsNil(row.Scope) {
		return false
	}
	return MatchTenant(row, filter) && (utils.IsNil(row.Namespace) && utils.IsNil(row.Principal) ||
		MatchNamespace(row, filter) && utils.IsNil(row.Principal) ||
		MatchPrincipal(row, filter))
}

func filterRoleForPrincipalByTenantNamespaceAndScope(filter *Data, row *Data) bool {
	if utils.IsNil(filter.Tenant) && utils.IsNil(filter.Principal) && utils.IsNil(filter.Namespace) && utils.IsNil(filter.Scope) || utils.IsNil(row.Role) {
		return false
	}
	return (MatchTenant(row, filter) && MatchPrincipal(row, filter)) ||
		(MatchNamespace(row, filter) && MatchPrincipal(row, filter)) ||
		(MatchScope(row, filter) && MatchPrincipal(row, filter))
}

func filterRoleForPrincipalByTenantAndNamespace(filter *Data, row *Data) bool {
	if utils.IsNil(filter.Tenant) && utils.IsNil(filter.Principal) && utils.IsNil(filter.Namespace) || utils.IsNil(row.Role) {
		return false
	}
	return (MatchTenant(row, filter) && MatchPrincipal(row, filter)) ||
		MatchNamespace(row, filter)
}

func filterRoleForPrincipalByTenantAndScope(filter *Data, row *Data) bool {
	if utils.IsNil(filter.Tenant) && utils.IsNil(filter.Principal) && utils.IsNil(filter.Scope) || utils.IsNil(row.Role) {
		return false
	}
	return (MatchTenant(row, filter) && MatchPrincipal(row, filter)) || MatchScope(row, filter)
}

func filterNamespaceForPrincipalByTenant(filter *Data, row *Data) bool {
	if utils.IsNil(filter.Tenant) && utils.IsNil(filter.Principal) || utils.IsNil(row.Namespace) {
		return false
	}
	return MatchTenant(row, filter) &&
		(utils.IsNil(row.Principal) || MatchPrincipal(row, filter))
}

func filterPrincipalByTenant(filter *Data, row *Data) bool {
	if utils.IsNil(filter.Tenant) && utils.IsNil(filter.Principal) {
		return false
	}
	return MatchPrincipal(row, filter) && MatchTenant(row, filter)
}

func filterScopePrincipalByTenant(filter *Data, row *Data) bool {
	if utils.IsNil(filter.Tenant) && utils.IsNil(filter.Principal) {
		return false
	}
	return MatchPrincipal(row, filter) && MatchTenant(row, filter) && !utils.IsNil(row.Scope) && !utils.IsNil(row.Role)
}

func MatchTenant(row *Data, filter *Data) bool {
	if utils.IsNil(row.Tenant) {
		return false
	}
	return utils.Match(row.Tenant, filter.Tenant)
}

func MatchNamespace(row *Data, filter *Data) bool {
	if utils.IsNil(row.Namespace) {
		return false
	}
	return utils.Match(row.Namespace, filter.Namespace)
}

func MatchScope(row *Data, filter *Data) bool {
	if utils.IsNil(row.Scope) {
		return false
	}
	return utils.Match(row.Scope, filter.Scope)
}

func MatchPrincipal(row *Data, filter *Data) bool {
	if utils.IsNil(row.Principal) {
		return false
	}
	return utils.Match(row.Principal, filter.Principal)
}

func MatchRole(row *Data, filter *Data) bool {
	if utils.IsNil(row.Role) {
		return false
	}
	return utils.Match(row.Role, filter.Role)
}
