package v1

type Option struct {
	tenant        any
	namespace     any
	scope         any
	resourceGroup any
	activity      any
}

func WithTenant(tenant any) func(*Option) {
	return func(s *Option) {
		s.tenant = tenant
	}
}

func WithNamespace(namespace any) func(*Option) {
	return func(s *Option) {
		s.namespace = namespace
	}
}

func WithScope(scope any) func(*Option) {
	return func(s *Option) {
		s.scope = scope
	}
}

func WithResourceGroup(resourceGroup any) func(*Option) {
	return func(s *Option) {
		s.resourceGroup = resourceGroup
	}
}

func WithActivity(activity any) func(*Option) {
	return func(s *Option) {
		s.activity = activity
	}
}
