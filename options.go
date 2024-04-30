package permission

type Option struct {
	userID   string
	tenant   string
	module   string
	entity   string
	group    string
	activity string
	manager  *RoleManager
}

func WithTenant(tenant string) func(*Option) {
	return func(s *Option) {
		s.tenant = tenant
	}
}

func WithModule(module string) func(*Option) {
	return func(s *Option) {
		s.module = module
	}
}

func WithEntity(entity string) func(*Option) {
	return func(s *Option) {
		s.entity = entity
	}
}

func WithGroup(group string) func(*Option) {
	return func(s *Option) {
		s.group = group
	}
}

func WithActivity(activity string) func(*Option) {
	return func(s *Option) {
		s.activity = activity
	}
}

func WithManager(manager *RoleManager) func(*Option) {
	return func(s *Option) {
		s.manager = manager
	}
}
