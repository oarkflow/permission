package v1

import (
	"errors"
	"slices"

	"github.com/oarkflow/permission/maps"

	"github.com/oarkflow/permission/utils"
)

type Attribute struct {
	resource string
	action   string
}

func (a Attribute) String(delimiter ...string) string {
	delim := " "
	if len(delimiter) > 0 {
		delim = delimiter[0]
	}
	return a.resource + delim + a.action
}

type AttributeGroup struct {
	permissions maps.IMap[string, *Attribute]
	id          string
}

func (a *AttributeGroup) AddAttributes(attrs ...*Attribute) {
	for _, attr := range attrs {
		a.permissions.Set(attr.String(), attr)
	}
}

// Role represents a principal role with its permissions
type Role struct {
	permissions maps.IMap[string, *AttributeGroup]
	descendants maps.IMap[string, *Role]
	id          string
	lock        bool
}

func (r *Role) Lock() {
	r.lock = true
}

func (r *Role) ID() string {
	return r.id
}

func (r *Role) Unlock() {
	r.lock = false
}

func (r *Role) Has(resourceGroup, permissionName string, allowedDescendants ...string) bool {
	resourceGroupPermissions, ok := r.permissions.Get(resourceGroup)
	if !ok || resourceGroupPermissions == nil {
		return false
	}
	if _, ok := resourceGroupPermissions.permissions.Get(permissionName); ok {
		return true
	}
	matched := false
	resourceGroupPermissions.permissions.ForEach(func(perm string, _ *Attribute) bool {
		if utils.MatchResource(permissionName, perm) {
			matched = true
			return false
		}
		return true
	})
	if matched {
		return true
	}
	totalD := len(allowedDescendants)
	// Check inherited permissions recursively
	for _, descendant := range r.GetDescendantRoles() {
		if totalD > 0 {
			if slices.Contains(allowedDescendants, descendant.id) {
				if descendant.Has(resourceGroup, permissionName, allowedDescendants...) {
					return true
				}
			}
		} else {
			if descendant.Has(resourceGroup, permissionName, allowedDescendants...) {
				return true
			}
		}
	}
	return false
}

func (r *Role) GetDescendantRoles() []*Role {
	var descendants []*Role
	r.descendants.ForEach(func(_ string, child *Role) bool {
		descendants = append(descendants, child)
		descendants = append(descendants, child.GetDescendantRoles()...)
		return true
	})
	return descendants
}

// AddDescendent adds a new permission to the role
func (r *Role) AddDescendent(descendants ...*Role) error {
	if r.lock {
		return errors.New("changes not allowed")
	}
	for _, descendant := range descendants {
		if _, ok := r.descendants.Get(descendant.id); !ok {
			r.descendants.Set(descendant.id, descendant)
		}
	}
	return nil
}

// AddPermission adds a new permission to the role
func (r *Role) AddPermission(resourceGroup string, permissions ...*Attribute) error {
	if r.lock {
		return errors.New("changes not allowed")
	}
	resourceGroupAttributes, exists := r.permissions.Get(resourceGroup)
	if !exists || resourceGroupAttributes == nil {
		resourceGroupAttributes = &AttributeGroup{
			id:          resourceGroup,
			permissions: maps.New[string, *Attribute](),
		}
	}
	perm := resourceGroupAttributes.permissions
	for _, permission := range permissions {
		if _, ok := perm.Get(permission.String()); !ok {
			perm.Set(permission.String(), permission)
		}
	}
	r.permissions.Set(resourceGroup, resourceGroupAttributes)
	return nil
}

func (r *Role) AddPermissionResourceGroup(resourceGroup *AttributeGroup) error {
	if r.lock {
		return errors.New("changes not allowed")
	}
	if _, ok := r.permissions.Get(resourceGroup.id); !ok {
		r.permissions.Set(resourceGroup.id, resourceGroup)
	}
	return nil
}

func (r *Role) GetResourceGroupPermissions(resourceGroup string) (permissions []*Attribute) {
	if grp, exists := r.permissions.Get(resourceGroup); exists {
		grp.permissions.ForEach(func(_ string, attr *Attribute) bool {
			permissions = append(permissions, attr)
			return true
		})
	}
	return
}

func (r *Role) GetAllImplicitPermissions(perm ...map[string][]Attribute) map[string][]Attribute {
	var grpPermissions map[string][]Attribute
	if len(perm) > 0 {
		grpPermissions = perm[0]
	} else {
		grpPermissions = make(map[string][]Attribute)
	}
	r.permissions.ForEach(func(resourceGroup string, grp *AttributeGroup) bool {
		var permissions []Attribute
		grp.permissions.ForEach(func(_ string, attr *Attribute) bool {
			permissions = append(permissions, *attr)
			return true
		})
		grpPermissions[resourceGroup] = append(grpPermissions[resourceGroup], permissions...)
		return true
	})
	for _, descendant := range r.GetDescendantRoles() {
		descendant.GetAllImplicitPermissions(grpPermissions)
	}
	return grpPermissions
}

func (r *Role) GetPermissions() map[string][]Attribute {
	grpPermissions := make(map[string][]Attribute)
	r.permissions.ForEach(func(resourceGroup string, grp *AttributeGroup) bool {
		var permissions []Attribute
		grp.permissions.ForEach(func(_ string, attr *Attribute) bool {
			permissions = append(permissions, *attr)
			return true
		})
		grpPermissions[resourceGroup] = permissions
		return true
	})
	return grpPermissions
}
