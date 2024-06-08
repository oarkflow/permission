package permission

import (
	"github.com/oarkflow/permission/trie"
)

func filterTenantsByPrincipal(filter *trie.Data, row *trie.Data) bool {
	return trie.FilterByFields(filter, row, func(d *trie.Data) any { return d.PrincipalID }) && !trie.IsNil(row.TenantID)
}

func filterTenant(filter *trie.Data, row *trie.Data) bool {
	return trie.FilterByFields(filter, row, func(d *trie.Data) any { return d.TenantID }) && !trie.IsNil(row.TenantID)
}

func filterScopeByPrincipal(filter *trie.Data, row *trie.Data) bool {
	return trie.FilterByFields(filter, row, func(d *trie.Data) any { return d.PrincipalID }) && !trie.IsNil(row.ScopeID) && !trie.IsNil(row.TenantID)
}

func filterRoleByTenant(filter *trie.Data, row *trie.Data) bool {
	return trie.FilterByFields(filter, row, func(d *trie.Data) any { return d.TenantID }, func(d *trie.Data) any { return d.RoleID })
}

func filterNamespaceByTenant(filter *trie.Data, row *trie.Data) bool {
	return trie.FilterByFields(filter, row, func(d *trie.Data) any { return d.TenantID }) && !trie.IsNil(row.NamespaceID)
}

func filterScopeByTenant(filter *trie.Data, row *trie.Data) bool {
	return trie.FilterByFields(filter, row, func(d *trie.Data) any { return d.TenantID }) && !trie.IsNil(row.ScopeID)
}

func filterScopeForPrincipalByTenant(filter *trie.Data, row *trie.Data) bool {
	if trie.IsNil(filter.TenantID) && trie.IsNil(filter.PrincipalID) || trie.IsNil(row.ScopeID) {
		return false
	}
	return trie.FilterByFields(filter, row, func(d *trie.Data) any { return d.TenantID }) && (trie.IsNil(row.PrincipalID) || trie.MatchesFilter(row.PrincipalID, filter.PrincipalID))
}

func filterScopeForPrincipalByNamespace(filter *trie.Data, row *trie.Data) bool {
	if trie.IsNil(filter.NamespaceID) && trie.IsNil(filter.PrincipalID) || trie.IsNil(row.ScopeID) {
		return false
	}
	return !trie.IsNil(row.TenantID) && (trie.IsNil(row.PrincipalID) || trie.MatchesFilter(row.PrincipalID, filter.PrincipalID))
}

func filterScopeForPrincipalByTenantAndNamespace(filter *trie.Data, row *trie.Data) bool {
	if trie.IsNil(filter.TenantID) && trie.IsNil(filter.PrincipalID) && trie.IsNil(filter.NamespaceID) || trie.IsNil(row.ScopeID) {
		return false
	}
	return trie.FilterByFields(filter, row, func(d *trie.Data) any { return d.TenantID }) &&
		(trie.IsNil(row.NamespaceID) && trie.IsNil(row.PrincipalID) ||
			trie.MatchesFilter(row.NamespaceID, filter.NamespaceID) && trie.IsNil(row.PrincipalID) ||
			trie.MatchesFilter(row.PrincipalID, filter.PrincipalID))
}

func filterRoleForPrincipalByTenantNamespaceAndScope(filter *trie.Data, row *trie.Data) bool {
	if trie.IsNil(filter.TenantID) && trie.IsNil(filter.PrincipalID) && trie.IsNil(filter.NamespaceID) && trie.IsNil(filter.ScopeID) || trie.IsNil(row.RoleID) {
		return false
	}
	return trie.FilterByFields(filter, row, func(d *trie.Data) any { return d.TenantID }, func(d *trie.Data) any { return d.PrincipalID }) ||
		(trie.MatchesFilter(row.NamespaceID, filter.NamespaceID) && trie.MatchesFilter(row.PrincipalID, filter.PrincipalID)) ||
		(trie.MatchesFilter(row.ScopeID, filter.ScopeID) && trie.MatchesFilter(row.PrincipalID, filter.PrincipalID))
}

func filterRoleForPrincipalByTenantAndNamespace(filter *trie.Data, row *trie.Data) bool {
	if trie.IsNil(filter.TenantID) && trie.IsNil(filter.PrincipalID) && trie.IsNil(filter.NamespaceID) || trie.IsNil(row.RoleID) {
		return false
	}
	return trie.FilterByFields(filter, row, func(d *trie.Data) any { return d.TenantID }, func(d *trie.Data) any { return d.PrincipalID }) ||
		trie.MatchesFilter(row.NamespaceID, filter.NamespaceID)
}

func filterRoleForPrincipalByTenantAndScope(filter *trie.Data, row *trie.Data) bool {
	if trie.IsNil(filter.TenantID) && trie.IsNil(filter.PrincipalID) && trie.IsNil(filter.ScopeID) || trie.IsNil(row.RoleID) {
		return false
	}
	return trie.FilterByFields(filter, row, func(d *trie.Data) any { return d.TenantID }, func(d *trie.Data) any { return d.PrincipalID }) ||
		trie.MatchesFilter(row.ScopeID, filter.ScopeID)
}

func filterNamespaceForPrincipalByTenant(filter *trie.Data, row *trie.Data) bool {
	if trie.IsNil(filter.TenantID) && trie.IsNil(filter.PrincipalID) || trie.IsNil(row.NamespaceID) {
		return false
	}
	return trie.FilterByFields(filter, row, func(d *trie.Data) any { return d.TenantID }) &&
		(trie.IsNil(row.PrincipalID) || trie.MatchesFilter(row.PrincipalID, filter.PrincipalID))
}
