package permission

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/oarkflow/maps"

	"github.com/oarkflow/permission/utils"
)

// Principal represents a user with a role
type Principal struct {
	id string
}

func (p *Principal) ID() string {
	return p.id
}

type TenantPrincipal struct {
	TenantID             string
	PrincipalID          string
	RoleID               string
	NamespaceID          string
	ScopeID              string
	CanManageDescendants bool
}

type PrincipalRole struct {
	tenant               *Tenant
	namespace            *Namespace
	scope                *Scope
	principalID          string
	roleID               string
	canManageDescendents bool
}

type RoleManager struct {
	tenants          maps.IMap[string, *Tenant]
	namespaces       maps.IMap[string, *Namespace]
	scopes           maps.IMap[string, *Scope]
	principals       maps.IMap[string, *Principal]
	roles            maps.IMap[string, *Role]
	attributes       maps.IMap[string, *Attribute]
	attributeGroups  maps.IMap[string, *AttributeGroup]
	tenantPrincipals map[string]struct{}
}

func New() *RoleManager {
	return &RoleManager{
		tenants:          maps.New[string, *Tenant](),
		namespaces:       maps.New[string, *Namespace](),
		scopes:           maps.New[string, *Scope](),
		principals:       maps.New[string, *Principal](),
		roles:            maps.New[string, *Role](),
		attributes:       maps.New[string, *Attribute](),
		attributeGroups:  maps.New[string, *AttributeGroup](),
		tenantPrincipals: make(map[string]struct{}),
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

func (u *RoleManager) TotalRoles() uintptr {
	return u.roles.Len()
}

func (u *RoleManager) TotalNamespaces() uintptr {
	return u.namespaces.Len()
}

func (u *RoleManager) TotalScopes() uintptr {
	return u.scopes.Len()
}

func (u *RoleManager) TotalTenants() uintptr {
	return u.tenants.Len()
}

func (u *RoleManager) TotalPrincipals() uintptr {
	return u.principals.Len()
}

func (u *RoleManager) Attributes() (data []string) {
	u.attributes.ForEach(func(id string, _ *Attribute) bool {
		data = append(data, id)
		return true
	})
	return
}

func (u *RoleManager) AddRole(role *Role) *Role {
	if r, exists := u.roles.Get(role.id); exists {
		return r
	}
	u.roles.Set(role.id, role)
	return role
}

func (u *RoleManager) AddRoles(roles ...*Role) {
	for _, role := range roles {
		u.AddRole(role)
	}
}

func (u *RoleManager) GetRole(role string) (*Role, bool) {
	return u.roles.Get(role)
}

func (u *RoleManager) Roles() (data []string) {
	u.roles.ForEach(func(id string, _ *Role) bool {
		data = append(data, id)
		return true
	})
	return
}

func (u *RoleManager) AddTenant(data *Tenant) *Tenant {
	data.manager = u
	if d, ok := u.tenants.Get(data.id); ok {
		return d
	}
	u.tenants.Set(data.id, data)
	return data
}

func (u *RoleManager) AddTenants(tenants ...*Tenant) {
	for _, data := range tenants {
		u.AddTenant(data)
	}
}

func (u *RoleManager) GetTenant(id string) (*Tenant, bool) {
	return u.tenants.Get(id)
}

func (u *RoleManager) Tenants() (data []string) {
	u.tenants.ForEach(func(id string, _ *Tenant) bool {
		data = append(data, id)
		return true
	})
	return
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

func (u *RoleManager) AddPrincipal(data *Principal) *Principal {
	if d, ok := u.principals.Get(data.id); ok {
		return d
	}
	u.principals.Set(data.id, data)
	return data
}

func (u *RoleManager) AddPrincipals(principals ...*Principal) {
	for _, data := range principals {
		u.AddPrincipal(data)
	}
}

func (u *RoleManager) GetPrincipal(id string) (*Principal, bool) {
	return u.principals.Get(id)
}

func (u *RoleManager) Principals() (data []string) {
	u.principals.ForEach(func(id string, _ *Principal) bool {
		data = append(data, id)
		return true
	})
	return
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

func getNamespaceID(n *Namespace) string {
	if n == nil {
		return ""
	}
	return n.ID()
}

func getScopeID(n *Scope) string {
	if n == nil {
		return ""
	}
	return n.ID()
}

func getTenantPrincipals(hash string) TenantPrincipal {
	parts := strings.Split(hash, "_")
	m := false
	if parts[5] == "true" {
		m = true
	}
	return TenantPrincipal{
		TenantID:             parts[2],
		PrincipalID:          parts[0],
		RoleID:               parts[1],
		NamespaceID:          parts[3],
		ScopeID:              parts[4],
		CanManageDescendants: m,
	}
}

func (u *RoleManager) AddPrincipalRole(principalID string, roleID string, tenant *Tenant, namespace *Namespace, scope *Scope, canManageDescendants ...bool) {
	manageDescendants := true
	if len(canManageDescendants) > 0 {
		manageDescendants = canManageDescendants[0]
	}
	h := fmt.Sprintf("%s_%s_%s_%s_%s_%v", principalID, roleID, tenant.ID(), getNamespaceID(namespace), getScopeID(scope), manageDescendants)
	if _, exists := u.tenantPrincipals[h]; !exists {
		u.tenantPrincipals[h] = struct{}{}
	}
}

func (u *RoleManager) GetTenantsForPrincipal(principalID string) (tenants []string, err error) {
	for tenantPrincipal := range u.tenantPrincipals {
		unmarshalled := getTenantPrincipals(tenantPrincipal)
		if unmarshalled.PrincipalID == principalID {
			tenants = append(tenants, unmarshalled.TenantID)
		}
	}
	tenants = slices.Compact(tenants)
	return
}

type PrincipalPermissions struct {
	TenantPrincipal
	Permissions map[string][]Attribute
}

func (u *RoleManager) GetPrincipalRoles(tenant, principalID string) (data []TenantPrincipal) {
	for tenantPrincipal := range u.tenantPrincipals {
		unmarshalled := getTenantPrincipals(tenantPrincipal)
		if unmarshalled.PrincipalID == principalID && unmarshalled.TenantID == tenant {
			data = append(data, unmarshalled)
		}
	}
	return
}

func (u *RoleManager) GetPermissionsForPrincipal(tenant, principalID string) (data []PrincipalPermissions) {
	for tenantPrincipal := range u.tenantPrincipals {
		unmarshalled := getTenantPrincipals(tenantPrincipal)
		if unmarshalled.PrincipalID == principalID && unmarshalled.TenantID == tenant {
			if unmarshalled.RoleID != "" {
				if r, ok := u.roles.Get(unmarshalled.RoleID); ok {
					d := PrincipalPermissions{
						TenantPrincipal: unmarshalled,
					}
					d.Permissions = r.GetPermissions()
					data = append(data, d)
				}
			}
		}
	}
	return
}

func (u *RoleManager) GetPrincipalRolesByTenant(tenant string) (data []TenantPrincipal) {
	for tenantPrincipal := range u.tenantPrincipals {
		unmarshalled := getTenantPrincipals(tenantPrincipal)
		if unmarshalled.TenantID == tenant {
			data = append(data, unmarshalled)
		}
	}
	return
}

func (u *RoleManager) AddPermissionsToRole(roleID, attributeGroupID string, attrs ...*Attribute) error {
	role, ok := u.roles.Get(roleID)
	if !ok {
		return errors.New("no role available")
	}
	attributeGroup, ok := u.attributeGroups.Get(attributeGroupID)
	if !ok {
		return errors.New("no attribute group available")
	}
	for _, attr := range attrs {
		if _, ok := attributeGroup.permissions.Get(attr.String()); !ok {
			return fmt.Errorf("attribute '%s' not associated to the group '%s'", attr.String(), attributeGroupID)
		}
	}
	return role.AddPermission(attributeGroupID, attrs...)
}

func (u *RoleManager) GetRolePermissions(roleID string) (map[string][]Attribute, error) {
	role, ok := u.roles.Get(roleID)
	if !ok {
		return nil, errors.New("no role available")
	}
	return role.GetPermissions(), nil
}

func (u *RoleManager) GetAllowedRoles(principalRoles []TenantPrincipal, namespace, scope string) []string {
	if principalRoles == nil {
		return nil
	}
	// Reusable slices
	namespaceScopes := stringSlice.Get()
	namespaceRoles := stringSlice.Get()
	scopes := stringSlice.Get()
	allowedRoles := stringSlice.Get()
	principalTenantRole := principalRoleSlice.Get()
	principalNamespaceScopeRole := principalRoleSlice.Get()
	defer func() {
		stringSlice.Put(namespaceScopes)
		stringSlice.Put(namespaceRoles)
		stringSlice.Put(scopes)
		stringSlice.Put(allowedRoles)
		principalRoleSlice.Put(principalTenantRole)
		principalRoleSlice.Put(principalNamespaceScopeRole)
	}()
	tenantID := principalRoles[0].TenantID
	tenant, _ := u.tenants.Get(tenantID)
	mod, modExists := tenant.namespaces.Get(namespace)
	_, entExists := tenant.scopes.Get(scope)
	if (scope != "" && !entExists) || (namespace != "" && !modExists) {
		return nil
	}
	if modExists {
		mod.scopes.ForEach(func(id string, _ *Scope) bool {
			namespaceScopes = append(namespaceScopes, id)
			return true
		})
		mod.roles.ForEach(func(id string, _ *Role) bool {
			namespaceRoles = append(namespaceRoles, id)
			return true
		})
	}
	for _, pRole := range principalRoles {
		if pRole.ScopeID != "" {
			scopes = append(scopes, pRole.ScopeID)
		}
		if pRole.NamespaceID != "" && pRole.ScopeID != "" { // if role for namespace and scope
			principalNamespaceScopeRole = append(principalNamespaceScopeRole, pRole)
		} else if pRole.NamespaceID == "" && pRole.ScopeID == "" { // if role for tenant
			principalTenantRole = append(principalTenantRole, pRole)
		}
	}
	if len(namespaceRoles) > 0 {
		for _, modRole := range namespaceRoles {
			allowedRoles = append(allowedRoles, modRole)
		}
	} else {
		for _, r := range principalTenantRole {
			allowedRoles = append(allowedRoles, r.RoleID)
		}
	}

	noTenantScopes := !slices.Contains(scopes, scope) && len(principalTenantRole) == 0
	noNamespaceScopes := len(namespaceScopes) > 0 && !slices.Contains(namespaceScopes, scope)
	if noTenantScopes || noNamespaceScopes {
		return nil
	}

	if namespace != "" && scope != "" && len(principalNamespaceScopeRole) > 0 {
		for _, r := range principalNamespaceScopeRole {
			if r.NamespaceID == namespace && r.ScopeID == scope {
				allowedRoles = append(allowedRoles, r.RoleID)
			}
		}
	}

	for _, role := range allowedRoles {
		if _, ok := tenant.roles.Get(role); !ok {
			return nil
		}
	}
	return slices.Compact(allowedRoles)
}
func (u *RoleManager) Authorize(principalID string, options ...func(*Option)) bool {
	svr := &Option{}
	for _, o := range options {
		o(svr)
	}

	if _, exists := u.GetPrincipal(principalID); !exists {
		return false
	}

	// Check if only tenant is provided
	if svr.tenant != nil && svr.namespace == nil && svr.scope == nil && svr.resourceGroup == nil && svr.activity == nil {
		return u.authorizeForTenant(utils.ToString(svr.tenant))
	}

	// Check if only namespace is provided
	if svr.namespace != nil && svr.tenant == "" && svr.scope == nil && svr.resourceGroup == nil && svr.activity == nil {
		return u.authorizeForNamespace(principalID, utils.ToString(svr.namespace))
	}

	// Check if only scope is provided
	if svr.scope != nil && svr.tenant == "" && svr.namespace == nil && svr.resourceGroup == nil && svr.activity == nil {
		return u.authorizeForScope(principalID, utils.ToString(svr.scope))
	}

	// Check if only activity is provided
	if svr.activity != nil && svr.tenant == "" && svr.namespace == nil && svr.scope == nil && svr.resourceGroup == nil {
		return u.authorizeForActivity(principalID, utils.ToString(svr.activity))
	}

	// Handle complex combinations of options
	return u.authorizeComplex(svr, principalID)
}

func (u *RoleManager) authorizeForTenant(tenantID string) bool {
	_, exists := u.GetTenant(tenantID)
	return exists
}

func (u *RoleManager) authorizeForNamespace(principalID, namespace string) bool {
	tenants, err := u.GetTenantsForPrincipal(principalID)
	if err != nil {
		return false
	}
	for _, t := range tenants {
		if tenant, exists := u.tenants.Get(t); exists {
			if _, ok := tenant.namespaces.Get(namespace); ok {
				return true
			}
		}
	}
	return false
}

func (u *RoleManager) authorizeForScope(principalID, scope string) bool {
	tenants, err := u.GetTenantsForPrincipal(principalID)
	if err != nil {
		return false
	}
	for _, t := range tenants {
		if tenant, exists := u.tenants.Get(t); exists {
			if _, ok := tenant.scopes.Get(scope); ok {
				principalRoles := u.GetPrincipalRoles(tenant.id, principalID)
				for _, t := range principalRoles {
					if t.ScopeID == scope {
						return true
					}
				}
			}
		}

	}
	return false
}

func (u *RoleManager) authorizeForActivity(principalID, activity string) bool {
	tenants, err := u.GetTenantsForPrincipal(principalID)
	if err != nil {
		return false
	}
	var roleIDs []string
	for _, tenant := range tenants {
		roleIDs = append(roleIDs, u.GetAllowedRoles(u.GetPrincipalRoles(tenant, principalID), "", "")...)
	}
	roleIDs = slices.Compact(roleIDs)
	roles := make(map[string]*Role)
	for _, r := range roleIDs {
		if role, ex := u.roles.Get(r); ex {
			roles[r] = role
		}
	}
	for _, role := range roles {
		if role.Has("", activity, roleIDs...) {
			return true
		}
	}

	return false
}

func (u *RoleManager) authorizeComplex(svr *Option, principalID string) bool {
	tenantID := svr.tenant
	namespace := utils.ToString(svr.namespace)
	scope := utils.ToString(svr.scope)
	resourceGroup := utils.ToString(svr.resourceGroup)
	activity := utils.ToString(svr.activity)

	tenant, exists := u.GetTenant(utils.ToString(tenantID))
	if !exists {
		return false
	}

	principalRoles := u.GetPrincipalRoles(utils.ToString(tenantID), principalID)
	if principalRoles == nil {
		return false
	}
	if namespace != "" {
		if _, ok := tenant.namespaces.Get(namespace); !ok {
			return false
		}
	}

	if scope != "" {
		if _, ok := tenant.scopes.Get(scope); !ok {
			return false
		}
	}
	roles := make(map[string]*Role)
	for _, r := range principalRoles {
		if role, ex := u.roles.Get(r.RoleID); ex {
			roles[r.RoleID] = role
		}
	}
	allowedRoles := u.GetAllowedRoles(principalRoles, namespace, scope)
	allowedRoleIDs := u.getAllowedRoleIDs(tenant, allowedRoles)
	for _, role := range roles {
		if role.Has(resourceGroup, activity, allowedRoleIDs...) {
			return true
		}
	}

	return false
}

func (u *RoleManager) getAllowedRoleIDs(tenant *Tenant, roles []string) []string {
	var allowed []string
	tenant.roles.ForEach(func(_ string, r *Role) bool {
		for _, rt := range roles {
			if r.id == rt {
				allowed = append(allowed, r.id)
			}
		}
		return true
	})
	return allowed
}
