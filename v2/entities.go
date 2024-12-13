package v2

import (
	"sync"
	"time"
)

type Permission struct {
	Resource string
	Action   string
	Category string
}

func NewPermission(category, resource, method string) *Permission {
	return &Permission{Category: category, Resource: resource, Action: method}
}

type Role struct {
	Name        string
	Permissions map[string]struct{}
	Expiry      *time.Time // Optional expiry time for the role
	m           sync.RWMutex
}

func NewRole(name string, expiry ...*time.Time) *Role {
	var exp *time.Time
	if len(expiry) > 0 {
		exp = expiry[0]
	}
	return &Role{Name: name, Permissions: make(map[string]struct{}), Expiry: exp}
}

// IsExpired checks if the role has expired.
func (r *Role) IsExpired() bool {
	r.m.RLock()
	defer r.m.RUnlock()
	if r.Expiry == nil {
		return false // Role does not expire
	}
	return time.Now().After(*r.Expiry)
}

// SetExpiry sets the expiry time for the role.
func (r *Role) SetExpiry(expiry time.Time) {
	r.m.Lock()
	defer r.m.Unlock()
	r.Expiry = &expiry
}

// ClearExpiry clears the expiry time for the role, making it permanent.
func (r *Role) ClearExpiry() {
	r.m.Lock()
	defer r.m.Unlock()
	r.Expiry = nil
}

type Principal struct {
	ID string
}

func NewPrincipal(name string) *Principal {
	return &Principal{ID: name}
}

type Scope struct {
	ID string
}

func NewScope(name string) *Scope {
	return &Scope{ID: name}
}

type Namespace struct {
	ID     string
	Scopes map[string]*Scope
}

func NewNamespace(name string) *Namespace {
	return &Namespace{ID: name, Scopes: make(map[string]*Scope)}
}

type Tenant struct {
	ID           string
	Namespaces   map[string]*Namespace
	DefaultNS    string
	ChildTenants map[string]*Tenant
	m            sync.RWMutex
}

func NewTenant(id string, defaultNamespace ...string) *Tenant {
	namespaces := make(map[string]*Namespace)
	var defaultNS string
	if len(defaultNamespace) > 0 {
		defaultNS = defaultNamespace[0]
		namespaces[defaultNS] = NewNamespace(defaultNS)
	}
	return &Tenant{
		ID:           id,
		DefaultNS:    defaultNS,
		Namespaces:   namespaces,
		ChildTenants: make(map[string]*Tenant),
	}
}
