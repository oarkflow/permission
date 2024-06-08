package permission

import (
	"github.com/oarkflow/permission/trie"
)

type Data struct {
	TenantID             any
	NamespaceID          any
	ScopeID              any
	PrincipalID          any
	RoleID               any
	CanManageDescendants any
}

func FilterFunc(filter *Data, node *Data) bool {
	if !trie.IsNil(filter.TenantID) && !trie.MatchesFilter(node.TenantID, filter.TenantID) {
		return false
	}
	if !trie.IsNil(filter.PrincipalID) && !trie.MatchesFilter(node.PrincipalID, filter.PrincipalID) {
		return false
	}
	if !trie.IsNil(filter.RoleID) && !trie.MatchesFilter(node.RoleID, filter.RoleID) {
		return false
	}
	if !trie.IsNil(filter.NamespaceID) && !trie.MatchesFilter(node.NamespaceID, filter.NamespaceID) {
		return false
	}
	if !trie.IsNil(filter.ScopeID) && !trie.MatchesFilter(node.ScopeID, filter.ScopeID) {
		return false
	}
	if !trie.IsNil(filter.CanManageDescendants) && filter.CanManageDescendants != node.CanManageDescendants {
		return false
	}
	return true
}

func filterTenantsByPrincipal(filter *Data, row *Data) bool {
	return trie.FilterByFields(filter, row, func(d *Data) any { return d.PrincipalID }) && !trie.IsNil(row.TenantID)
}

func filterTenant(filter *Data, row *Data) bool {
	return trie.FilterByFields(filter, row, func(d *Data) any { return d.TenantID }) && !trie.IsNil(row.TenantID)
}

func filterScopeByPrincipal(filter *Data, row *Data) bool {
	return trie.FilterByFields(filter, row, func(d *Data) any { return d.PrincipalID }) && !trie.IsNil(row.ScopeID) && !trie.IsNil(row.TenantID)
}

func filterRoleByTenant(filter *Data, row *Data) bool {
	return trie.FilterByFields(filter, row, func(d *Data) any { return d.TenantID }, func(d *Data) any { return d.RoleID })
}

func filterNamespaceByTenant(filter *Data, row *Data) bool {
	return trie.FilterByFields(filter, row, func(d *Data) any { return d.TenantID }) && !trie.IsNil(row.NamespaceID)
}

func filterScopeByTenant(filter *Data, row *Data) bool {
	return trie.FilterByFields(filter, row, func(d *Data) any { return d.TenantID }) && !trie.IsNil(row.ScopeID)
}

func filterScopeForPrincipalByTenant(filter *Data, row *Data) bool {
	if trie.IsNil(filter.TenantID) && trie.IsNil(filter.PrincipalID) || trie.IsNil(row.ScopeID) {
		return false
	}
	return trie.FilterByFields(filter, row, func(d *Data) any { return d.TenantID }) && (trie.IsNil(row.PrincipalID) || trie.MatchesFilter(row.PrincipalID, filter.PrincipalID))
}

func filterScopeForPrincipalByNamespace(filter *Data, row *Data) bool {
	if trie.IsNil(filter.NamespaceID) && trie.IsNil(filter.PrincipalID) || trie.IsNil(row.ScopeID) {
		return false
	}
	return !trie.IsNil(row.TenantID) && (trie.IsNil(row.PrincipalID) || trie.MatchesFilter(row.PrincipalID, filter.PrincipalID))
}

func filterScopeForPrincipalByTenantAndNamespace(filter *Data, row *Data) bool {
	if trie.IsNil(filter.TenantID) && trie.IsNil(filter.PrincipalID) && trie.IsNil(filter.NamespaceID) || trie.IsNil(row.ScopeID) {
		return false
	}
	return trie.FilterByFields(filter, row, func(d *Data) any { return d.TenantID }) &&
		(trie.IsNil(row.NamespaceID) && trie.IsNil(row.PrincipalID) ||
			trie.MatchesFilter(row.NamespaceID, filter.NamespaceID) && trie.IsNil(row.PrincipalID) ||
			trie.MatchesFilter(row.PrincipalID, filter.PrincipalID))
}

func filterRoleForPrincipalByTenantNamespaceAndScope(filter *Data, row *Data) bool {
	if trie.IsNil(filter.TenantID) && trie.IsNil(filter.PrincipalID) && trie.IsNil(filter.NamespaceID) && trie.IsNil(filter.ScopeID) || trie.IsNil(row.RoleID) {
		return false
	}
	return trie.FilterByFields(filter, row, func(d *Data) any { return d.TenantID }, func(d *Data) any { return d.PrincipalID }) ||
		(trie.MatchesFilter(row.NamespaceID, filter.NamespaceID) && trie.MatchesFilter(row.PrincipalID, filter.PrincipalID)) ||
		(trie.MatchesFilter(row.ScopeID, filter.ScopeID) && trie.MatchesFilter(row.PrincipalID, filter.PrincipalID))
}

func filterRoleForPrincipalByTenantAndNamespace(filter *Data, row *Data) bool {
	if trie.IsNil(filter.TenantID) && trie.IsNil(filter.PrincipalID) && trie.IsNil(filter.NamespaceID) || trie.IsNil(row.RoleID) {
		return false
	}
	return trie.FilterByFields(filter, row, func(d *Data) any { return d.TenantID }, func(d *Data) any { return d.PrincipalID }) ||
		trie.MatchesFilter(row.NamespaceID, filter.NamespaceID)
}

func filterRoleForPrincipalByTenantAndScope(filter *Data, row *Data) bool {
	if trie.IsNil(filter.TenantID) && trie.IsNil(filter.PrincipalID) && trie.IsNil(filter.ScopeID) || trie.IsNil(row.RoleID) {
		return false
	}
	return trie.FilterByFields(filter, row, func(d *Data) any { return d.TenantID }, func(d *Data) any { return d.PrincipalID }) ||
		trie.MatchesFilter(row.ScopeID, filter.ScopeID)
}

func filterNamespaceForPrincipalByTenant(filter *Data, row *Data) bool {
	if trie.IsNil(filter.TenantID) && trie.IsNil(filter.PrincipalID) || trie.IsNil(row.NamespaceID) {
		return false
	}
	return trie.FilterByFields(filter, row, func(d *Data) any { return d.TenantID }) &&
		(trie.IsNil(row.PrincipalID) || trie.MatchesFilter(row.PrincipalID, filter.PrincipalID))
}
