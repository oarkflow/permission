package permission

import (
	"github.com/oarkflow/permission/utils"
)

func WithAttributeGroup(activityGroup any) func(*Option) {
	return func(s *Option) {
		s.activityGroup = activityGroup
	}
}

func (u *RoleManager) AddAttributeGroup(attr *AttributeGroup) *AttributeGroup {
	if d, ok := u.attributeGroups.Get(attr.id); ok {
		return d
	}
	u.attributeGroups.Set(attr.id, attr)
	return attr
}

func (u *RoleManager) AddAttributeGroups(attrs ...*AttributeGroup) {
	for _, attr := range attrs {
		u.AddAttributeGroup(attr)
	}
}

func (u *RoleManager) GetAttributeGroup(id string) (*AttributeGroup, bool) {
	return u.attributeGroups.Get(id)
}

func (u *RoleManager) TotalAttributeGroups() int {
	return u.attributeGroups.Size()
}

type ScopeRoles struct {
	Scope any   `json:"scope"`
	Roles []any `json:"roles"`
}

func (u *RoleManager) GetScopesWithRolesForPrincipal(principalID, tenantID, namespaceID any) (response []ScopeRoles) {
	seen := make(map[any][]any)
	data := Data{Principal: principalID, Tenant: tenantID, Namespace: namespaceID}
	tenantPrincipals := u.search(data, filterPrincipalByTenant)
	if len(tenantPrincipals) == 0 {
		for tenant := range u.GetImplicitTenants(principalID.(string)) {
			if tenant == tenantID {
				continue
			}
			data.Tenant = tenant
			tenantPrincipals = u.search(data, filterPrincipalByTenant)
			if len(tenantPrincipals) > 0 {
				break
			}
		}
	}

	tenantNamespaceEntities := u.search(data, filterScopeByTenantAndNamespace)
	if len(tenantNamespaceEntities) == 0 {
		tenantNamespaceEntities = u.search(data, filterScopeByTenant)
	}
	tenantScopePrincipals := u.search(data, filterScopePrincipalByTenant)
	joinFn := func(p *Data, a *Data) bool {
		return MatchTenant(p, a)
	}
	combineFn := func(p *Data, a *Data) *Data {
		return &Data{
			Tenant:    p.Tenant,
			Scope:     p.Scope,
			Principal: a.Principal,
			Role:      a.Role,
		}
	}
	result := utils.JoinSlices(tenantNamespaceEntities, tenantPrincipals, joinFn, combineFn)
	result = append(result, tenantScopePrincipals...)
	for _, r := range result {
		seen[r.Scope] = append(seen[r.Scope], r.Role)
	}
	for scope, roles := range seen {
		response = append(response, ScopeRoles{
			Scope: scope,
			Roles: roles,
		})
	}
	clear(seen)
	return response
}
