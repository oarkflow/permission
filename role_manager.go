package permission

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/oarkflow/maps"

	"github.com/oarkflow/permission/utils"
)

// Principal represents a user with a role
type Principal struct {
	ID string
}

type PrincipalRole struct {
	Tenant               *Tenant
	Namespace            *Namespace
	Scope                *Scope
	PrincipalID          string
	RoleID               string
	CanManageDescendants bool
}

type TenantPrincipal struct {
	Tenant               *Tenant
	Principal            *Principal
	PrincipalRoles       []*PrincipalRole
	CanManageDescendants bool
}

type RoleManager struct {
	tenants          maps.IMap[string, *Tenant]
	namespaces       maps.IMap[string, *Namespace]
	scopes           maps.IMap[string, *Scope]
	principals       maps.IMap[string, *Principal]
	roles            maps.IMap[string, *Role]
	tenantPrincipals maps.IMap[string, *TenantPrincipal]
	attributes       maps.IMap[string, *Attribute]
	attributeGroups  maps.IMap[string, *AttributeGroup]
}

func New() *RoleManager {
	return &RoleManager{
		tenants:          maps.New[string, *Tenant](),
		namespaces:       maps.New[string, *Namespace](),
		scopes:           maps.New[string, *Scope](),
		principals:       maps.New[string, *Principal](),
		roles:            maps.New[string, *Role](),
		tenantPrincipals: maps.New[string, *TenantPrincipal](),
		attributes:       maps.New[string, *Attribute](),
		attributeGroups:  maps.New[string, *AttributeGroup](),
	}
}

func (u *RoleManager) AddAttribute(attr *Attribute) *Attribute {
	u.attributes.GetOrSet(attr.String(), attr)
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
	u.attributeGroups.GetOrSet(attr.ID, attr)
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

func (u *RoleManager) Attributes() map[string]*Attribute {
	return u.attributes.AsMap()
}

func (u *RoleManager) AddRole(role *Role) *Role {
	u.roles.GetOrSet(role.ID, role)
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

func (u *RoleManager) Roles() map[string]*Role {
	return u.roles.AsMap()
}

func (u *RoleManager) AddTenant(data *Tenant) *Tenant {
	data.manager = u
	u.tenants.GetOrSet(data.ID, data)
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

func (u *RoleManager) Tenants() map[string]*Tenant {
	return u.tenants.AsMap()
}

func (u *RoleManager) AddNamespace(data *Namespace) *Namespace {
	u.namespaces.GetOrSet(data.ID, data)
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

func (u *RoleManager) Namespaces() map[string]*Namespace {
	return u.namespaces.AsMap()
}

func (u *RoleManager) AddPrincipal(data *Principal) *Principal {
	u.principals.GetOrSet(data.ID, data)
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

func (u *RoleManager) Principals() map[string]*Principal {
	return u.principals.AsMap()
}

func (u *RoleManager) AddScope(data *Scope) *Scope {
	u.scopes.GetOrSet(data.ID, data)
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

func (u *RoleManager) Scopes() map[string]*Scope {
	return u.scopes.AsMap()
}

func (u *RoleManager) AddPrincipalRole(principalID string, roleID string, tenant *Tenant, namespace *Namespace, scope *Scope, canManageDescendants ...bool) {
	manageDescendants := true
	if len(canManageDescendants) > 0 {
		manageDescendants = canManageDescendants[0]
	}
	role := &PrincipalRole{
		PrincipalID:          principalID,
		RoleID:               roleID,
		Tenant:               tenant,
		Namespace:            namespace,
		Scope:                scope,
		CanManageDescendants: manageDescendants,
	}
	tenantPrincipal, ok := u.tenantPrincipals.Get(tenant.ID)
	if !ok {
		tenantPrincipal = &TenantPrincipal{
			Tenant:               tenant,
			Principal:            &Principal{ID: principalID},
			CanManageDescendants: manageDescendants,
		}
	}
	tenantPrincipal.PrincipalRoles = append(tenantPrincipal.PrincipalRoles, role)
	u.tenantPrincipals.GetOrSet(tenant.ID, tenantPrincipal)
}

func (u *RoleManager) GetTenantsForPrincipal(principalID string) (tenants []string, err error) {
	u.tenantPrincipals.ForEach(func(id string, tenant *TenantPrincipal) bool {
		for _, r := range tenant.PrincipalRoles {
			if r.PrincipalID == principalID {
				tenants = append(tenants, id)
			}
		}
		return true
	})
	tenants = slices.Compact(tenants)
	return
}

func (u *RoleManager) GetPrincipalRoles(tenant, principalID string) *TenantPrincipal {
	instance, ok := u.tenantPrincipals.Get(tenant)
	if !ok {
		return nil
	}
	roles := make([]*PrincipalRole, 0, len(instance.PrincipalRoles))
	principalFound := false
	for _, ut := range instance.PrincipalRoles {
		if ut.PrincipalID == principalID {
			principalFound = true
			roles = append(roles, ut)
		}
	}
	if !principalFound {
		return nil
	}
	return &TenantPrincipal{
		Tenant:               instance.Tenant,
		Principal:            instance.Principal,
		CanManageDescendants: instance.CanManageDescendants,
		PrincipalRoles:       roles,
	}
}

func (u *RoleManager) GetPrincipalRolesByTenant(tenant string) []*PrincipalRole {
	principalRoles, ok := u.tenantPrincipals.Get(tenant)
	if !ok {
		return nil
	}
	return principalRoles.PrincipalRoles
}

func (u *RoleManager) GetRolesForPrincipalByTenant(tenant, principalID string) (ut []*PrincipalRole) {
	principalRoles, ok := u.tenantPrincipals.Get(tenant)
	if !ok {
		return
	}
	for _, ur := range principalRoles.PrincipalRoles {
		if ur.PrincipalID == principalID {
			ut = append(ut, ur)
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

func (u *RoleManager) GetAllowedRoles(principalRoles *TenantPrincipal, namespace, scope string) []string {
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

	mod, modExists := principalRoles.Tenant.Namespaces.Get(namespace)
	_, entExists := principalRoles.Tenant.Scopes.Get(scope)
	if (scope != "" && !entExists) || (namespace != "" && !modExists) {
		return nil
	}

	if modExists {
		mod.Scopes.ForEach(func(id string, _ *Scope) bool {
			namespaceScopes = append(namespaceScopes, id)
			return true
		})
		mod.Roles.ForEach(func(id string, _ *Role) bool {
			namespaceRoles = append(namespaceRoles, id)
			return true
		})
	}

	for _, principalRole := range principalRoles.PrincipalRoles {
		if principalRole.Scope != nil {
			scopes = append(scopes, principalRole.Scope.ID)
		}
		if principalRole.Namespace != nil && principalRole.Scope != nil { // if role for namespace and scope
			principalNamespaceScopeRole = append(principalNamespaceScopeRole, principalRole)
		} else if principalRole.Namespace == nil && principalRole.Scope == nil { // if role for tenant
			principalTenantRole = append(principalTenantRole, principalRole)
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
			if r.Namespace.ID == namespace && r.Scope.ID == scope {
				allowedRoles = append(allowedRoles, r.RoleID)
			}
		}
	}

	for _, role := range allowedRoles {
		if _, ok := principalRoles.Tenant.Roles.Get(role); !ok {
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
	_, exists := u.GetPrincipal(principalID)
	if !exists {
		return false
	}

	if svr.tenant == "" {
		return false
	}
	_, exists = u.GetTenant(svr.tenant)
	if !exists {
		return false
	}
	var allowed []string
	tenantPrincipal := u.GetPrincipalRoles(svr.tenant, principalID)
	if tenantPrincipal == nil {
		return false
	}
	var principalRoles []*Role
	roles := u.GetAllowedRoles(tenantPrincipal, svr.namespace, svr.scope)
	tenantPrincipal.Tenant.Roles.ForEach(func(_ string, r *Role) bool {
		for _, rt := range roles {
			if r.ID == rt {
				principalRoles = append(principalRoles, r)
			}
		}
		allowed = append(allowed, r.ID)
		return true
	})
	for _, role := range principalRoles {
		if role.Has(svr.resourceGroup, svr.activity, allowed...) {
			return true
		}
	}
	return false
}

type Config struct {
	TenantKey        string
	NamespaceKey     string
	ScopeKey         string
	RoleKey          string
	ResourceGroupKey string
	ResourceKey      string
	ActionKey        string
}

func (u *RoleManager) LoadTenant(tenantKey string, data []map[string]any) error {
	for _, item := range data {
		tenantVal := utils.ToString(item[tenantKey])
		if tenantVal != "" {
			u.AddTenant(NewTenant(tenantVal))
		}
	}
	return nil
}

func (u *RoleManager) LoadScope(scopeKey string, data []map[string]any) error {
	for _, item := range data {
		scopeVal := utils.ToString(item[scopeKey])
		if scopeVal != "" {
			u.AddScope(NewScope(scopeVal))
		}
	}
	return nil
}

func (u *RoleManager) LoadTenantScope(config Config, data []map[string]any) error {
	for _, item := range data {
		tenantVal := utils.ToString(item[config.TenantKey])
		scopeVal := utils.ToString(item[config.ScopeKey])
		namespaceVal := utils.ToString(item[config.NamespaceKey])
		var tenant *Tenant
		var scopeID, namespaceID string
		tenant, exists := u.GetTenant(tenantVal)
		if !exists {
			tenant = u.AddTenant(NewTenant(tenantVal))
		}
		if namespaceVal != "" {
			att, exists := u.GetNamespace(namespaceVal)
			if !exists {
				att = u.AddNamespace(NewNamespace(namespaceVal))
			}
			namespaceID = att.ID
			if tenant != nil {
				tenant.AddNamespace(att)
			}
		}
		if scopeVal != "" {
			att, exists := u.GetScope(scopeVal)
			if !exists {
				att = u.AddScope(NewScope(scopeVal))
			}

			if tenant != nil {
				tenant.AddScopes(att)
				if namespaceID != "" {
					tenant.AddScopesToNamespace(namespaceID, scopeID)
				}
			}
		}
	}
	return nil
}

func (u *RoleManager) LoadNamespace(namespaceKey string, data []map[string]any) error {
	for _, item := range data {
		namespaceVal := utils.ToString(item[namespaceKey])
		if namespaceVal != "" {
			u.AddNamespace(NewNamespace(namespaceVal))
		}
	}
	return nil
}

func (u *RoleManager) LoadRoles(roleKey string, data []map[string]any) error {
	for _, item := range data {
		roleVal := utils.ToString(item[roleKey])
		if roleVal != "" {
			u.AddRole(NewRole(roleVal))
		}
	}
	return nil
}

func (u *RoleManager) LoadAttributes(groupKey, attributeKey, actionKey string, data []map[string]any) error {
	for _, item := range data {
		groupVal := utils.ToString(item[groupKey])
		attributeVal := utils.ToString(item[attributeKey])
		actionVal := utils.ToString(item[actionKey])
		group, ex := u.GetAttributeGroup(groupVal)
		if !ex {
			group = u.AddAttributeGroup(NewAttributeGroup(groupVal))
		}
		if attributeVal != "" {
			p := &Attribute{Resource: attributeVal, Action: actionVal}
			u.AddAttribute(p)
			group.AddAttributes(p)
		}
	}
	return nil
}

func (u *RoleManager) Load(config Config, data []map[string]any) error {
	for _, item := range data {
		tenantKey := utils.ToString(item[config.TenantKey])
		if tenantKey == "" {
			continue
		}
		var tenant *Tenant
		tenant, exists := u.GetTenant(tenantKey)
		if !exists {
			tenant = u.AddTenant(NewTenant(tenantKey))
		}
		var perm *Attribute
		var scopeID, namespaceID string
		namespaceKey := utils.ToString(item[config.NamespaceKey])
		scopeKey := utils.ToString(item[config.ScopeKey])
		roleKey := utils.ToString(item[config.RoleKey])
		resource := utils.ToString(item[config.ResourceKey])
		resourceGroup := utils.ToString(item[config.ResourceGroupKey])
		action := utils.ToString(item[config.ActionKey])
		if resource != "" {
			p := &Attribute{Resource: resource, Action: action}
			att, exists := u.GetAttribute(p.String())
			if !exists {
				att = u.AddAttribute(p)
			}
			perm = att
		}

		if namespaceKey != "" {
			att, exists := u.GetNamespace(namespaceKey)
			if !exists {
				att = u.AddNamespace(NewNamespace(namespaceKey))
			}
			namespaceID = att.ID
			if tenant != nil {
				tenant.AddNamespace(att)
			}
		}
		if scopeKey != "" {
			att, exists := u.GetScope(scopeKey)
			if !exists {
				att = u.AddScope(NewScope(scopeKey))
			}

			if tenant != nil {
				tenant.AddScopes(att)
				if namespaceID != "" {
					tenant.AddScopesToNamespace(namespaceID, scopeID)
				}
			}
		}
		if roleKey != "" {
			att, exists := u.GetRole(roleKey)
			if !exists {
				att = u.AddRole(NewRole(roleKey))
			}
			if perm != nil {
				att.AddPermission(resourceGroup, perm)
			}
			if tenant != nil {
				tenant.AddRole(att)
				if namespaceID != "" {
					tenant.AddRolesToNamespace(namespaceID, att.ID)
				}
			}
		}
	}

	return nil
}

func (u *RoleManager) LoadBytes(config Config, bt []byte) error {
	var data []map[string]any
	err := json.Unmarshal(bt, &data)
	if err != nil {
		return err
	}
	return u.Load(config, data)
}

func (u *RoleManager) LoadFile(config Config, file string) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	return u.LoadBytes(config, data)
}
