package v2

// Principal represents a user with a role
type Principal struct {
	id string
}

func (p *Principal) ID() string {
	return p.id
}

func (u *RoleManager) AddPrincipal(data *Principal) *Principal {
	if d, ok := u.principals.Get(data.id); ok {
		return d
	}
	u.principals.Set(data.id, data)
	return data
}

func (u *RoleManager) AddPrincipals(principals ...*Principal) {
	for _, data := range principals {
		u.AddPrincipal(data)
	}
}

func (u *RoleManager) GetPrincipal(id string) (*Principal, bool) {
	return u.principals.Get(id)
}

func (u *RoleManager) Principals() (data []string) {
	u.principals.ForEach(func(id string, _ *Principal) bool {
		data = append(data, id)
		return true
	})
	return
}
