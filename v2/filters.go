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

func filterScopeForPrincipalByTenantAndNamespace(filter *trie.Data, row *trie.Data) bool {
	if (filter.TenantID == nil && filter.PrincipalID == nil && filter.NamespaceID == nil) || row.ScopeID == nil {
		return false
	}
	return (row.TenantID == filter.TenantID && row.NamespaceID == nil && row.PrincipalID == nil) ||
		(row.TenantID == filter.TenantID && row.NamespaceID == filter.NamespaceID && row.PrincipalID == nil) ||
		(row.TenantID == filter.TenantID && row.NamespaceID == filter.NamespaceID && row.PrincipalID == filter.PrincipalID)
}

func filterNamespaceForPrincipalByTenant(filter *trie.Data, row *trie.Data) bool {
	if (filter.TenantID == nil && filter.PrincipalID == nil) || row.NamespaceID == nil {
		return false
	}
	return (row.TenantID == filter.TenantID && row.PrincipalID == nil) || (row.TenantID == filter.TenantID && row.PrincipalID == filter.PrincipalID)
}
