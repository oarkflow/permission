package loader

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/oarkflow/permission"
)

type Config struct {
	TenantKey        string
	NamespaceKey     string
	ScopeKey         string
	RoleKey          string
	ResourceGroupKey string
	ResourceKey      string
	ActionKey        string
}

type Loader struct {
	cfg Config
}

func New(cfg Config) *Loader {
	return &Loader{cfg: cfg}
}

func (l *Loader) Load(data []map[string]any) (*permission.RoleManager, error) {
	config := l.cfg
	authorizer := permission.New()
	for _, item := range data {
		tenantKey := ToString(item[config.TenantKey])
		if tenantKey == "" {
			continue
		}
		var tenant *permission.Tenant
		tenant, exists := authorizer.GetTenant(tenantKey)
		if !exists {
			tenant = authorizer.AddTenant(permission.NewTenant(tenantKey))
		}
		var perm *permission.Attribute
		var scopeID, namespaceID string
		namespaceKey := ToString(item[config.NamespaceKey])
		scopeKey := ToString(item[config.ScopeKey])
		roleKey := ToString(item[config.RoleKey])
		resource := ToString(item[config.ResourceKey])
		resourceGroup := ToString(item[config.ResourceGroupKey])
		action := ToString(item[config.ActionKey])
		if resource != "" {
			p := &permission.Attribute{Resource: resource, Action: action}
			att, exists := authorizer.GetAttribute(p.String())
			if !exists {
				att = authorizer.AddAttribute(p)
			}
			perm = att
		}

		if namespaceKey != "" {
			att, exists := authorizer.GetNamespace(namespaceKey)
			if !exists {
				att = authorizer.AddNamespace(permission.NewNamespace(namespaceKey))
			}
			namespaceID = att.ID
			if tenant != nil {
				tenant.AddNamespace(att)
			}
		}
		if scopeKey != "" {
			att, exists := authorizer.GetScope(scopeKey)
			if !exists {
				att = authorizer.AddScope(permission.NewScope(scopeKey))
			}

			if tenant != nil {
				tenant.AddScopes(att)
				if namespaceID != "" {
					tenant.AddScopesToNamespace(namespaceID, scopeID)
				}
			}
		}
		if roleKey != "" {
			att, exists := authorizer.GetRole(roleKey)
			if !exists {
				att = authorizer.AddRole(permission.NewRole(roleKey))
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

	return authorizer, nil
}

func (l *Loader) LoadBytes(bt []byte) (*permission.RoleManager, error) {
	var data []map[string]any
	err := json.Unmarshal(bt, &data)
	if err != nil {
		return nil, err
	}
	return l.Load(data)
}

func (l *Loader) LoadFile(file string) (*permission.RoleManager, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return l.LoadBytes(data)
}

func ToString(val any) string {
	switch val := val.(type) {
	case string:
		return val
	case nil:
		return ""
	case fmt.Stringer:
		return val.String()
	default:
		return fmt.Sprintf("%v", val)
	}
}
