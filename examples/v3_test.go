package main

import (
	"testing"
)

func TestAuthorize(t *testing.T) {
	// Set up roles
	adminRole := Role{
		Name: "Admin",
		Permissions: []Permission{
			{Resource: "dashboard", Method: "read", Category: "page"},
			{Resource: "users", Method: "write", Category: "backend"},
		},
		ChildRoles: []string{"Editor"},
	}

	editorRole := Role{
		Name: "Editor",
		Permissions: []Permission{
			{Resource: "posts", Method: "edit", Category: "backend"},
		},
		ChildRoles: []string{},
	}

	roleMap := map[string]Role{
		"Admin":  adminRole,
		"Editor": editorRole,
	}

	// Set up tenants and scopes
	rootTenant := &Tenant{
		ID:     "root",
		Name:   "Root Tenant",
		Parent: nil,
		Services: []Scope{
			{Name: "scope1", Namespace: "service1"},
		},
	}
	childTenant := &Tenant{
		ID:     "child",
		Name:   "Child Tenant",
		Parent: rootTenant,
		Services: []Scope{
			{Name: "scope2", Namespace: "service2"},
		},
	}

	tenants := map[string]*Tenant{
		"root":  rootTenant,
		"child": childTenant,
	}

	// Set up user roles
	userRoles := []UserRole{
		{UserID: "user1", TenantID: "root", ScopeName: "scope1", RoleName: "Admin"},
	}

	// Define test cases
	tests := []struct {
		name     string
		request  Request
		expected bool
	}{
		// Positive Test Cases
		{
			name: "Valid request with direct role",
			request: Request{
				UserID:    "user1",
				TenantID:  "child",
				ScopeName: "scope1",
				Category:  "backend",
				Resource:  "posts",
				Method:    "edit",
			},
			expected: true,
		},
		{
			name: "Valid request with inherited scope from parent tenant",
			request: Request{
				UserID:    "user1",
				TenantID:  "child",
				ScopeName: "scope1",
				Category:  "page",
				Resource:  "dashboard",
				Method:    "read",
			},
			expected: true,
		},

		// Negative Test Cases
		{
			name: "Invalid scope not in tenant hierarchy",
			request: Request{
				UserID:    "user1",
				TenantID:  "child",
				ScopeName: "scope3", // Non-existent scope
				Category:  "backend",
				Resource:  "posts",
				Method:    "edit",
			},
			expected: false,
		},
		{
			name: "Valid scope but no matching role for the user",
			request: Request{
				UserID:    "user2", // User not in userRoles
				TenantID:  "child",
				ScopeName: "scope1",
				Category:  "backend",
				Resource:  "posts",
				Method:    "edit",
			},
			expected: false,
		},
		{
			name: "Valid scope but user lacks the required permission",
			request: Request{
				UserID:    "user1",
				TenantID:  "child",
				ScopeName: "scope1",
				Category:  "backend",
				Resource:  "posts",
				Method:    "delete", // Permission not granted
			},
			expected: false,
		},
		{
			name: "Invalid tenant in the request",
			request: Request{
				UserID:    "user1",
				TenantID:  "invalidTenant", // Non-existent tenant
				ScopeName: "scope1",
				Category:  "backend",
				Resource:  "posts",
				Method:    "edit",
			},
			expected: false,
		},
	}

	// Run tests
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := authorize(tt.request, userRoles, tenants, roleMap)
			if result != tt.expected {
				t.Errorf("Test %s failed: expected %v, got %v", tt.name, tt.expected, result)
			}
		})
	}
}
