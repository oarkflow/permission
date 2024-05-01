package permission

type Option struct {
	tenant        string
	namespace     string
	scope         string
	resourceGroup string
	activity      string
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

func WithResourceGroup(resourceGroup string) func(*Option) {
	return func(s *Option) {
		s.resourceGroup = resourceGroup
	}
}

func WithActivity(activity string) func(*Option) {
	return func(s *Option) {
		s.activity = activity
	}
}
