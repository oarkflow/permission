package v2

import (
	"fmt"
	"sync"
	"time"

	"github.com/oarkflow/permission/utils"
)

type PrincipalRole struct {
	Principal         string
	Tenant            string
	Scope             string
	Namespace         string
	Role              string
	Expiry            *time.Time // Optional expiry time for the user role
	ManageChildTenant bool
}

// IsExpired checks if the user role has expired.
func (pr *PrincipalRole) IsExpired() bool {
	if pr.Expiry == nil {
		return false // User role does not expire
	}
	return time.Now().After(*pr.Expiry)
}

// SetExpiry sets the expiry time for the user role.
func (pr *PrincipalRole) SetExpiry(expiry time.Time) {
	pr.Expiry = &expiry
}

// ClearExpiry clears the expiry time for the user role, making it permanent.
func (pr *PrincipalRole) ClearExpiry() {
	pr.Expiry = nil
}

type Request struct {
	Principal string
	Tenant    string
	Namespace string
	Scope     string
	Resource  string
	Action    string
}

type Authorizer struct {
	roleDAG     *RoleDAG
	userRoles   []PrincipalRole
	userRoleMap map[string]map[string][]PrincipalRole
	tenants     map[string]*Tenant
	namespaces  map[string]*Namespace
	scopes      map[string]*Scope
	principals  map[string]*Principal
	permissions map[string]*Permission
	parentCache map[string]*Tenant
	m           sync.RWMutex
}

func NewAuthorizer() *Authorizer {
	return &Authorizer{
		roleDAG:     NewRoleDAG(),
		tenants:     make(map[string]*Tenant),
		parentCache: make(map[string]*Tenant),
		namespaces:  make(map[string]*Namespace),
		scopes:      make(map[string]*Scope),
		principals:  make(map[string]*Principal),
		userRoleMap: make(map[string]map[string][]PrincipalRole),
	}
}

func (a *Authorizer) AddPrincipalRole(userRole ...PrincipalRole) {
	a.m.Lock()
	defer a.m.Unlock()
	for _, ur := range userRole {
		a.userRoles = append(a.userRoles, ur)
		if a.userRoleMap[ur.Principal] == nil {
			a.userRoleMap[ur.Principal] = make(map[string][]PrincipalRole)
		}
		a.userRoleMap[ur.Principal][ur.Tenant] = append(a.userRoleMap[ur.Principal][ur.Tenant], ur)
	}
}

var (
	scopedPermissionsPool = utils.New(func() map[string]struct{} { return make(map[string]struct{}) })
	globalPermissionsPool = utils.New(func() map[string]struct{} { return make(map[string]struct{}) })
	checkedTenantsPool    = utils.New(func() map[string]bool { return make(map[string]bool) })
)

func (a *Authorizer) resolvePrincipalRoles(userID, tenantID, namespace, scopeName string) (map[string]struct{}, error) {
	tenant, exists := a.tenants[tenantID]
	if !exists {
		return nil, fmt.Errorf("invalid tenant: %v", tenantID)
	}
	globalPermissions := globalPermissionsPool.Get()
	scopedPermissions := scopedPermissionsPool.Get()
	checkedTenants := checkedTenantsPool.Get()
	clear(scopedPermissions)
	clear(globalPermissions)
	clear(checkedTenants)
	defer func() {
		scopedPermissionsPool.Put(scopedPermissions)
		globalPermissionsPool.Put(globalPermissions)
		checkedTenantsPool.Put(checkedTenants)
	}()
	var traverse func(current *Tenant) error
	traverse = func(current *Tenant) error {
		if checkedTenants[current.ID] {
			return nil
		}
		checkedTenants[current.ID] = true
		for _, userRole := range a.userRoles {
			if userRole.Principal != userID || userRole.Tenant != current.ID {
				continue
			}
			// Skip expired user roles
			if userRole.IsExpired() {
				continue
			}
			if userRole.Namespace == "" || userRole.Namespace == namespace {
				permissions := a.roleDAG.ResolvePermissions(userRole.Role)
				if userRole.Scope == scopeName {
					for perm := range permissions {
						scopedPermissions[perm] = struct{}{}
					}
				} else if userRole.Scope == "" {
					for perm := range permissions {
						globalPermissions[perm] = struct{}{}
					}
				}
			}
		}
		for _, userRole := range a.userRoles {
			if userRole.Principal == userID && userRole.Tenant == current.ID && userRole.ManageChildTenant {
				for _, child := range current.ChildTenants {
					if err := traverse(child); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	if err := traverse(tenant); err != nil {
		return nil, err
	}
	if len(scopedPermissions) > 0 {
		return scopedPermissions, nil
	}
	if len(globalPermissions) > 0 {
		return globalPermissions, nil
	}
	return nil, fmt.Errorf("no roleDAG or permissions found")
}

func (a *Authorizer) Authorize(request Request) bool {
	var tenantBuffer [10]*Tenant
	var targetTenants []*Tenant
	tenantCount := 0
	if request.Tenant == "" {
		tenants := a.findPrincipalTenants(request.Principal)
		tenantCount = len(tenants)
		if tenantCount <= len(tenantBuffer) {
			copy(tenantBuffer[:], tenants)
			targetTenants = tenantBuffer[:tenantCount]
		} else {
			targetTenants = tenants
		}
	} else {
		tenant, exists := a.tenants[request.Tenant]
		if !exists {
			return false
		}
		tenantBuffer[0] = tenant
		tenantCount = 1
		targetTenants = tenantBuffer[:tenantCount]
	}
	for _, tenant := range targetTenants {
		namespace := request.Namespace
		if namespace == "" {
			if tenant.DefaultNS != "" {
				namespace = tenant.DefaultNS
			} else if len(tenant.Namespaces) == 1 {
				for ns := range tenant.Namespaces {
					namespace = ns
					break
				}
			} else {
				continue
			}
		}
		ns, exists := tenant.Namespaces[namespace]
		if !exists {
			continue
		}
		if request.Scope != "" && !a.isScopeValidForNamespace(ns, request.Scope) {
			continue
		}
		permissions, err := a.resolvePrincipalRoles(request.Principal, tenant.ID, namespace, request.Scope)
		if err != nil {
			continue
		}
		for permission := range permissions {
			if matchPermission(permission, request) {
				return true
			}
		}
	}
	return false
}

func (a *Authorizer) isScopeValidForNamespace(ns *Namespace, scopeName string) bool {
	_, exists := ns.Scopes[scopeName]
	return exists
}

func (a *Authorizer) findPrincipalTenants(userID string) []*Tenant {
	tenantSet := make(map[string]*Tenant)
	for _, userRole := range a.userRoles {
		if userRole.Principal == userID && userRole.Tenant != "" {
			if tenant, exists := a.tenants[userRole.Tenant]; exists {
				tenantSet[userRole.Tenant] = tenant
			}
		}
	}

	// Pre-allocate the slice with the exact length of the map
	tenantList := make([]*Tenant, len(tenantSet))
	i := 0
	for _, tenant := range tenantSet {
		tenantList[i] = tenant // Populate the pre-allocated slice directly
		i++
	}
	return tenantList
}

func matchPermission(permission string, request Request) bool {
	if request.Resource == "" && request.Action == "" {
		return false
	}
	requestToCheck := request.Resource + " " + request.Action
	return utils.MatchResource(requestToCheck, permission)
}
