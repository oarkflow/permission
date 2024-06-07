package v2

func WithScope(scope any) func(*Option) {
	return func(s *Option) {
		s.scope = scope
	}
}

type Scope struct {
	id string
}

func (s *Scope) ID() string {
	return s.id
}

func (u *RoleManager) AddScope(data *Scope) *Scope {
	if d, ok := u.scopes.Get(data.id); ok {
		return d
	}
	u.scopes.Set(data.id, data)
	return data
}

func (u *RoleManager) AddScopes(scopes ...*Scope) {
	for _, data := range scopes {
		u.AddScope(data)
	}
}

func (u *RoleManager) GetScope(id string) (*Scope, bool) {
	return u.scopes.Get(id)
}

func (u *RoleManager) Scopes() (data []string) {
	u.scopes.ForEach(func(id string, _ *Scope) bool {
		data = append(data, id)
		return true
	})
	return
}
