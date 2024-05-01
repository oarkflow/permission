package permission

type Option struct {
	tenant    string
	namespace string
	scope     string
	group     string
	activity  string
	manager   *RoleManager
}

func WithTenant(tenant string) func(*Option) {
	return func(s *Option) {
		s.tenant = tenant
	}
}

func WithNamespace(namespace string) func(*Option) {
	return func(s *Option) {
		s.namespace = namespace
	}
}

func WithScope(scope string) func(*Option) {
	return func(s *Option) {
		s.scope = scope
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
