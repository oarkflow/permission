package permission

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

func (u *RoleManager) TotalAttributeGroups() uintptr {
	return u.attributeGroups.Len()
}
