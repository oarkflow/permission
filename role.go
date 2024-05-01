package permission

import (
	"errors"
	"slices"

	"github.com/oarkflow/maps"
)

type Attribute struct {
	Resource string
	Action   string
}

func (a Attribute) String(delimiter ...string) string {
	delim := " "
	if len(delimiter) > 0 {
		delim = delimiter[0]
	}
	return a.Resource + delim + a.Action
}

type AttributeResourceGroup struct {
	ID          string
	permissions maps.IMap[string, Attribute]
}

// Role represents a principal role with its permissions
type Role struct {
	ID          string
	lock        bool
	permissions maps.IMap[string, *AttributeResourceGroup]
	descendants maps.IMap[string, *Role]
	manager     *RoleManager
}

func (r *Role) Lock() {
	r.lock = true
}

func (r *Role) Unlock() {
	r.lock = false
}

func (r *Role) Has(resourceGroup, permissionName string, allowedDescendants ...string) bool {
	resourceGroupPermissions, ok := r.permissions.Get(resourceGroup)
	if !ok {
		return false
	}
	if _, ok := resourceGroupPermissions.permissions.Get(permissionName); ok {
		return true
	}
	matched := false
	resourceGroupPermissions.permissions.ForEach(func(perm string, _ Attribute) bool {
		if MatchResource(permissionName, perm) {
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
			if slices.Contains(allowedDescendants, descendant.ID) {
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
		r.descendants.Set(descendant.ID, descendant)
	}
	return nil
}

// AddPermission adds a new permission to the role
func (r *Role) AddPermission(resourceGroup string, permissions ...Attribute) error {
	if r.lock {
		return errors.New("changes not allowed")
	}
	resourceGroupAttributes, exists := r.permissions.Get(resourceGroup)
	if !exists || resourceGroupAttributes == nil {
		resourceGroupAttributes = &AttributeResourceGroup{
			ID:          resourceGroup,
			permissions: maps.New[string, Attribute](),
		}
	}
	for _, permission := range permissions {
		resourceGroupAttributes.permissions.Set(permission.String(), permission)
	}
	r.permissions.Set(resourceGroup, resourceGroupAttributes)
	return nil
}

func (r *Role) AddPermissionResourceGroup(resourceGroup *AttributeResourceGroup) error {
	if r.lock {
		return errors.New("changes not allowed")
	}
	r.permissions.Set(resourceGroup.ID, resourceGroup)
	return nil
}

func (r *Role) GetResourceGroupPermissions(resourceGroup string) (permissions []Attribute) {
	if grp, exists := r.permissions.Get(resourceGroup); exists {
		grp.permissions.ForEach(func(_ string, attr Attribute) bool {
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
	r.permissions.ForEach(func(resourceGroup string, grp *AttributeResourceGroup) bool {
		var permissions []Attribute
		grp.permissions.ForEach(func(_ string, attr Attribute) bool {
			permissions = append(permissions, attr)
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
	r.permissions.ForEach(func(resourceGroup string, grp *AttributeResourceGroup) bool {
		var permissions []Attribute
		grp.permissions.ForEach(func(_ string, attr Attribute) bool {
			permissions = append(permissions, attr)
			return true
		})
		grpPermissions[resourceGroup] = permissions
		return true
	})
	return grpPermissions
}
