package permission

func WithNamespace(namespace any) func(*Option) {
	return func(s *Option) {
		s.namespace = namespace
	}
}

type Namespace struct {
	id string
}

func (n *Namespace) ID() string {
	return n.id
}

func (u *RoleManager) AddNamespace(data *Namespace) *Namespace {
	if d, ok := u.namespaces.Get(data.id); ok {
		return d
	}
	u.namespaces.Set(data.id, data)
	return data
}

func (u *RoleManager) AddNamespaces(nms ...*Namespace) {
	for _, data := range nms {
		u.AddNamespace(data)
	}
}

func (u *RoleManager) GetNamespace(id string) (*Namespace, bool) {
	return u.namespaces.Get(id)
}

func (u *RoleManager) Namespaces() (data []string) {
	u.namespaces.ForEach(func(id string, _ *Namespace) bool {
		data = append(data, id)
		return true
	})
	return
}
