package v2

import (
	"github.com/oarkflow/permission/trie"
)

func isNil(value any) bool {
	return value == nil
}

func matchesFilter(value, filter any) bool {
	return !isNil(filter) && value == filter
}

func filterByFields(filter *trie.Data, row *trie.Data, fields ...func(*trie.Data) any) bool {
	for _, field := range fields {
		if isNil(field(row)) || !matchesFilter(field(row), field(filter)) {
			return false
		}
	}
	return true
}

func filterTenantsByPrincipal(filter *trie.Data, row *trie.Data) bool {
	return filterByFields(filter, row, func(d *trie.Data) any { return d.PrincipalID }) && !isNil(row.TenantID)
}

func filterTenant(filter *trie.Data, row *trie.Data) bool {
	return filterByFields(filter, row, func(d *trie.Data) any { return d.TenantID }) && !isNil(row.TenantID)
}

func filterScopeByPrincipal(filter *trie.Data, row *trie.Data) bool {
	return filterByFields(filter, row, func(d *trie.Data) any { return d.PrincipalID }) && !isNil(row.ScopeID) && !isNil(row.TenantID)
}

func filterRoleByTenant(filter *trie.Data, row *trie.Data) bool {
	return filterByFields(filter, row, func(d *trie.Data) any { return d.TenantID }, func(d *trie.Data) any { return d.RoleID })
}

func filterNamespaceByTenant(filter *trie.Data, row *trie.Data) bool {
	return filterByFields(filter, row, func(d *trie.Data) any { return d.TenantID }) && !isNil(row.NamespaceID)
}

func filterScopeByTenant(filter *trie.Data, row *trie.Data) bool {
	return filterByFields(filter, row, func(d *trie.Data) any { return d.TenantID }) && !isNil(row.ScopeID)
}

func filterScopeForPrincipalByTenant(filter *trie.Data, row *trie.Data) bool {
	if isNil(filter.TenantID) && isNil(filter.PrincipalID) || isNil(row.ScopeID) {
		return false
	}
	return filterByFields(filter, row, func(d *trie.Data) any { return d.TenantID }) && (isNil(row.PrincipalID) || matchesFilter(row.PrincipalID, filter.PrincipalID))
}

func filterScopeForPrincipalByNamespace(filter *trie.Data, row *trie.Data) bool {
	if isNil(filter.NamespaceID) && isNil(filter.PrincipalID) || isNil(row.ScopeID) {
		return false
	}
	return !isNil(row.TenantID) && (isNil(row.PrincipalID) || matchesFilter(row.PrincipalID, filter.PrincipalID))
}

func filterScopeForPrincipalByTenantAndNamespace(filter *trie.Data, row *trie.Data) bool {
	if isNil(filter.TenantID) && isNil(filter.PrincipalID) && isNil(filter.NamespaceID) || isNil(row.ScopeID) {
		return false
	}
	return filterByFields(filter, row, func(d *trie.Data) any { return d.TenantID }) &&
		(isNil(row.NamespaceID) && isNil(row.PrincipalID) ||
			matchesFilter(row.NamespaceID, filter.NamespaceID) && isNil(row.PrincipalID) ||
			matchesFilter(row.PrincipalID, filter.PrincipalID))
}

func filterRoleForPrincipalByTenantNamespaceAndScope(filter *trie.Data, row *trie.Data) bool {
	if isNil(filter.TenantID) && isNil(filter.PrincipalID) && isNil(filter.NamespaceID) && isNil(filter.ScopeID) || isNil(row.RoleID) {
		return false
	}
	return filterByFields(filter, row, func(d *trie.Data) any { return d.TenantID }, func(d *trie.Data) any { return d.PrincipalID }) ||
		(matchesFilter(row.NamespaceID, filter.NamespaceID) && matchesFilter(row.PrincipalID, filter.PrincipalID)) ||
		(matchesFilter(row.ScopeID, filter.ScopeID) && matchesFilter(row.PrincipalID, filter.PrincipalID))
}

func filterRoleForPrincipalByTenantAndNamespace(filter *trie.Data, row *trie.Data) bool {
	if isNil(filter.TenantID) && isNil(filter.PrincipalID) && isNil(filter.NamespaceID) || isNil(row.RoleID) {
		return false
	}
	return filterByFields(filter, row, func(d *trie.Data) any { return d.TenantID }, func(d *trie.Data) any { return d.PrincipalID }) ||
		matchesFilter(row.NamespaceID, filter.NamespaceID)
}

func filterRoleForPrincipalByTenantAndScope(filter *trie.Data, row *trie.Data) bool {
	if isNil(filter.TenantID) && isNil(filter.PrincipalID) && isNil(filter.ScopeID) || isNil(row.RoleID) {
		return false
	}
	return filterByFields(filter, row, func(d *trie.Data) any { return d.TenantID }, func(d *trie.Data) any { return d.PrincipalID }) ||
		matchesFilter(row.ScopeID, filter.ScopeID)
}

func filterNamespaceForPrincipalByTenant(filter *trie.Data, row *trie.Data) bool {
	if isNil(filter.TenantID) && isNil(filter.PrincipalID) || isNil(row.NamespaceID) {
		return false
	}
	return filterByFields(filter, row, func(d *trie.Data) any { return d.TenantID }) &&
		(isNil(row.PrincipalID) || matchesFilter(row.PrincipalID, filter.PrincipalID))
}
