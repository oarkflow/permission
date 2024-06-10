package permission

import (
	"github.com/oarkflow/permission/trie"
)

type Data struct {
	Tenant            any
	Namespace         any
	Scope             any
	Principal         any
	Role              any
	ManageDescendants any
}

func FilterFunc(filter *Data, node *Data) bool {
	if !trie.IsNil(filter.Tenant) && !trie.MatchesFilter(node.Tenant, filter.Tenant) {
		return false
	}
	if !trie.IsNil(filter.Principal) && !trie.MatchesFilter(node.Principal, filter.Principal) {
		return false
	}
	if !trie.IsNil(filter.Role) && !trie.MatchesFilter(node.Role, filter.Role) {
		return false
	}
	if !trie.IsNil(filter.Namespace) && !trie.MatchesFilter(node.Namespace, filter.Namespace) {
		return false
	}
	if !trie.IsNil(filter.Scope) && !trie.MatchesFilter(node.Scope, filter.Scope) {
		return false
	}
	if !trie.IsNil(filter.ManageDescendants) && filter.ManageDescendants != node.ManageDescendants {
		return false
	}
	return true
}

func filterTenantsByPrincipal(filter *Data, row *Data) bool {
	return trie.FilterByFields(filter, row, func(d *Data) any { return d.Principal }) && !trie.IsNil(row.Tenant)
}

func filterTenant(filter *Data, row *Data) bool {
	return trie.FilterByFields(filter, row, func(d *Data) any { return d.Tenant }) && !trie.IsNil(row.Tenant)
}

func filterScopeByPrincipal(filter *Data, row *Data) bool {
	return trie.FilterByFields(filter, row, func(d *Data) any { return d.Principal }) && !trie.IsNil(row.Scope) && !trie.IsNil(row.Tenant)
}

func filterRoleByTenant(filter *Data, row *Data) bool {
	return trie.FilterByFields(filter, row, func(d *Data) any { return d.Tenant }, func(d *Data) any { return d.Role })
}

func filterNamespaceByTenant(filter *Data, row *Data) bool {
	return trie.FilterByFields(filter, row, func(d *Data) any { return d.Tenant }) && !trie.IsNil(row.Namespace)
}

func filterScopeByTenant(filter *Data, row *Data) bool {
	return trie.FilterByFields(filter, row, func(d *Data) any { return d.Tenant }) && !trie.IsNil(row.Scope)
}

func filterScopeForPrincipalByTenant(filter *Data, row *Data) bool {
	if trie.IsNil(filter.Tenant) && trie.IsNil(filter.Principal) || trie.IsNil(row.Scope) {
		return false
	}
	return trie.FilterByFields(filter, row, func(d *Data) any { return d.Tenant }) && (trie.IsNil(row.Principal) || trie.MatchesFilter(row.Principal, filter.Principal))
}

func filterScopeForPrincipalByNamespace(filter *Data, row *Data) bool {
	if trie.IsNil(filter.Namespace) && trie.IsNil(filter.Principal) || trie.IsNil(row.Scope) {
		return false
	}
	return !trie.IsNil(row.Tenant) && (trie.IsNil(row.Principal) || trie.MatchesFilter(row.Principal, filter.Principal))
}

func filterScopeForPrincipalByTenantAndNamespace(filter *Data, row *Data) bool {
	if trie.IsNil(filter.Tenant) && trie.IsNil(filter.Principal) && trie.IsNil(filter.Namespace) || trie.IsNil(row.Scope) {
		return false
	}
	return trie.FilterByFields(filter, row, func(d *Data) any { return d.Tenant }) &&
		(trie.IsNil(row.Namespace) && trie.IsNil(row.Principal) ||
			trie.MatchesFilter(row.Namespace, filter.Namespace) && trie.IsNil(row.Principal) ||
			trie.MatchesFilter(row.Principal, filter.Principal))
}

func filterRoleForPrincipalByTenantNamespaceAndScope(filter *Data, row *Data) bool {
	if trie.IsNil(filter.Tenant) && trie.IsNil(filter.Principal) && trie.IsNil(filter.Namespace) && trie.IsNil(filter.Scope) || trie.IsNil(row.Role) {
		return false
	}
	return trie.FilterByFields(filter, row, func(d *Data) any { return d.Tenant }, func(d *Data) any { return d.Principal }) ||
		(trie.MatchesFilter(row.Namespace, filter.Namespace) && trie.MatchesFilter(row.Principal, filter.Principal)) ||
		(trie.MatchesFilter(row.Scope, filter.Scope) && trie.MatchesFilter(row.Principal, filter.Principal))
}

func filterRoleForPrincipalByTenantAndNamespace(filter *Data, row *Data) bool {
	if trie.IsNil(filter.Tenant) && trie.IsNil(filter.Principal) && trie.IsNil(filter.Namespace) || trie.IsNil(row.Role) {
		return false
	}
	return trie.FilterByFields(filter, row, func(d *Data) any { return d.Tenant }, func(d *Data) any { return d.Principal }) ||
		trie.MatchesFilter(row.Namespace, filter.Namespace)
}

func filterRoleForPrincipalByTenantAndScope(filter *Data, row *Data) bool {
	if trie.IsNil(filter.Tenant) && trie.IsNil(filter.Principal) && trie.IsNil(filter.Scope) || trie.IsNil(row.Role) {
		return false
	}
	return trie.FilterByFields(filter, row, func(d *Data) any { return d.Tenant }, func(d *Data) any { return d.Principal }) ||
		trie.MatchesFilter(row.Scope, filter.Scope)
}

func filterNamespaceForPrincipalByTenant(filter *Data, row *Data) bool {
	if trie.IsNil(filter.Tenant) && trie.IsNil(filter.Principal) || trie.IsNil(row.Namespace) {
		return false
	}
	return trie.FilterByFields(filter, row, func(d *Data) any { return d.Tenant }) &&
		(trie.IsNil(row.Principal) || trie.MatchesFilter(row.Principal, filter.Principal))
}
