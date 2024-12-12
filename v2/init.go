package v2

func (a *Authorizer) AddRoles(role ...*Role) {
	a.roleDAG.AddRole(role...)
}

func (a *Authorizer) AddRole(role *Role) *Role {
	a.AddRoles(role)
	return role
}

func (a *Authorizer) GetRole(val string) (*Role, bool) {
	role, ok := a.roleDAG.roles[val]
	return role, ok
}

func (a *Authorizer) AddPrincipals(p ...*Principal) {
	for _, principal := range p {
		a.AddPrincipal(principal)
	}
}

func (a *Authorizer) AddPrincipal(p *Principal) *Principal {
	a.m.Lock()
	defer a.m.Unlock()
	a.principals[p.ID] = p
	return p
}

func (a *Authorizer) GetPrincipal(val string) (*Principal, bool) {
	data, ok := a.principals[val]
	return data, ok
}

func (a *Authorizer) AddNamespaces(p ...*Namespace) {
	for _, namespace := range p {
		a.AddNamespace(namespace)
	}
}

func (a *Authorizer) AddNamespace(p *Namespace) *Namespace {
	a.m.Lock()
	defer a.m.Unlock()
	a.namespaces[p.ID] = p
	return p
}

func (a *Authorizer) GetNamespace(val string) (*Namespace, bool) {
	data, ok := a.namespaces[val]
	return data, ok
}

func (a *Authorizer) AddScopes(p ...*Scope) {
	for _, namespace := range p {
		a.AddScope(namespace)
	}
}

func (a *Authorizer) AddScope(p *Scope) *Scope {
	a.m.Lock()
	defer a.m.Unlock()
	a.scopes[p.ID] = p
	return p
}

func (a *Authorizer) GetScope(val string) (*Scope, bool) {
	data, ok := a.scopes[val]
	return data, ok
}

func (a *Authorizer) AddPermissions(p ...*Permission) {
	for _, namespace := range p {
		a.AddPermission(namespace)
	}
}

func (a *Authorizer) AddPermission(p *Permission) *Permission {
	a.m.Lock()
	defer a.m.Unlock()
	a.permissions[p.String()] = p
	return p
}

func (a *Authorizer) GetPermission(val string) (*Permission, bool) {
	data, ok := a.permissions[val]
	return data, ok
}

func (a *Authorizer) AddChildRole(parent string, child ...string) error {
	return a.roleDAG.AddChildRole(parent, child...)
}

func (a *Authorizer) AddTenants(tenants ...*Tenant) {
	for _, tenant := range tenants {
		a.AddTenant(tenant)
	}
}

func (a *Authorizer) AddTenant(tenant *Tenant) *Tenant {
	a.m.Lock()
	defer a.m.Unlock()
	a.tenants[tenant.ID] = tenant
	for _, child := range tenant.ChildTenants {
		a.parentCache[child.ID] = tenant
	}
	return tenant
}

func (a *Authorizer) GetTenant(id string) (*Tenant, bool) {
	a.m.Lock()
	defer a.m.Unlock()
	tenant, ok := a.tenants[id]
	return tenant, ok
}
