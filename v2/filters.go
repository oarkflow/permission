package v2

import (
	"github.com/oarkflow/permission/trie"
)

func filterTenantsByPrincipal(filter *trie.Data, row *trie.Data) bool {
	if filter.PrincipalID == nil {
		return false
	}
	return row.PrincipalID == filter.PrincipalID && row.TenantID != nil
}

func filterScopeByPrincipal(filter *trie.Data, row *trie.Data) bool {
	if filter.PrincipalID == nil || row.ScopeID == nil {
		return false
	}
	return row.PrincipalID == filter.PrincipalID && row.TenantID != nil
}

func filterRoleByTenant(filter *trie.Data, row *trie.Data) bool {
	return row.TenantID == filter.TenantID && row.RoleID != nil
}

func filterNamespaceByTenant(filter *trie.Data, row *trie.Data) bool {
	if filter.TenantID == nil {
		return false
	}
	return row.TenantID == filter.TenantID && row.NamespaceID != nil
}

func filterScopeByTenant(filter *trie.Data, row *trie.Data) bool {
	if filter.TenantID == nil {
		return false
	}
	return row.TenantID == filter.TenantID && row.ScopeID != nil
}

func filterScopeForPrincipalByTenant(filter *trie.Data, row *trie.Data) bool {
	if (filter.TenantID == nil && filter.PrincipalID == nil) || row.ScopeID == nil {
		return false
	}
	return (row.TenantID == filter.TenantID && row.PrincipalID == nil) || (row.TenantID == filter.TenantID && row.PrincipalID == filter.PrincipalID)
}

func filterScopeForPrincipalByNamespace(filter *trie.Data, row *trie.Data) bool {
	if (filter.NamespaceID == nil && filter.PrincipalID == nil) || row.ScopeID == nil {
		return false
	}
	return (row.TenantID != nil && row.PrincipalID == nil) || (row.TenantID == filter.TenantID && row.PrincipalID == filter.PrincipalID)
}

func filterScopeForPrincipalByTenantAndNamespace(filter *trie.Data, row *trie.Data) bool {
	if (filter.TenantID == nil && filter.PrincipalID == nil && filter.NamespaceID == nil) || row.ScopeID == nil {
		return false
	}
	return (row.TenantID == filter.TenantID && row.NamespaceID == nil && row.PrincipalID == nil) ||
		(row.TenantID == filter.TenantID && row.NamespaceID == filter.NamespaceID && row.PrincipalID == nil) ||
		(row.TenantID == filter.TenantID && row.NamespaceID == filter.NamespaceID && row.PrincipalID == filter.PrincipalID)
}

func filterRoleForPrincipalByTenantNamespaceAndScope(filter *trie.Data, row *trie.Data) bool {
	if (filter.TenantID == nil && filter.PrincipalID == nil && filter.NamespaceID == nil && filter.ScopeID == nil) || row.RoleID == nil {
		return false
	}
	return (row.TenantID == filter.TenantID && row.PrincipalID == filter.PrincipalID) ||
		(row.TenantID == filter.TenantID && row.NamespaceID == filter.NamespaceID && row.PrincipalID == filter.PrincipalID) ||
		(row.TenantID == filter.TenantID && row.ScopeID == filter.ScopeID && row.PrincipalID == filter.PrincipalID)
}

func filterRoleForPrincipalByTenantAndNamespace(filter *trie.Data, row *trie.Data) bool {
	if (filter.TenantID == nil && filter.PrincipalID == nil && filter.NamespaceID == nil) || row.RoleID == nil {
		return false
	}
	return (row.TenantID == filter.TenantID && row.PrincipalID == filter.PrincipalID) ||
		(row.TenantID == filter.TenantID && row.NamespaceID == filter.NamespaceID && row.PrincipalID == filter.PrincipalID)
}

func filterRoleForPrincipalByTenantAndScope(filter *trie.Data, row *trie.Data) bool {
	if (filter.TenantID == nil && filter.PrincipalID == nil && filter.ScopeID == nil) || row.RoleID == nil {
		return false
	}
	return (row.TenantID == filter.TenantID && row.PrincipalID == filter.PrincipalID) ||
		(row.TenantID == filter.TenantID && row.ScopeID == filter.ScopeID && row.PrincipalID == filter.PrincipalID)
}

func filterNamespaceForPrincipalByTenant(filter *trie.Data, row *trie.Data) bool {
	if (filter.TenantID == nil && filter.PrincipalID == nil) || row.NamespaceID == nil {
		return false
	}
	return (row.TenantID == filter.TenantID && row.PrincipalID == nil) || (row.TenantID == filter.TenantID && row.PrincipalID == filter.PrincipalID)
}
