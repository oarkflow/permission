package permission

func WithActivity(activity any) func(*Option) {
	return func(s *Option) {
		s.activity = activity
	}
}

func (u *RoleManager) AddAttribute(attr *Attribute) *Attribute {
	if d, ok := u.attributes.Get(attr.String()); ok {
		return d
	}
	u.attributes.Set(attr.String(), attr)
	return attr
}

func (u *RoleManager) AddAttributes(attrs ...*Attribute) {
	for _, attr := range attrs {
		u.AddAttribute(attr)
	}
}

func (u *RoleManager) GetAttribute(attr string) (*Attribute, bool) {
	return u.attributes.Get(attr)
}

func (u *RoleManager) TotalAttributes() uintptr {
	return u.attributes.Len()
}

func (u *RoleManager) Attributes() (data []string) {
	u.attributes.ForEach(func(id string, _ *Attribute) bool {
		data = append(data, id)
		return true
	})
	return
}
