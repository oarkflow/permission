package main_test

import (
	"fmt"
	"testing"
	"unsafe"
)

type TenantPrincipal struct {
	TenantID             any
	PrincipalID          any
	RoleID               any
	NamespaceID          any
	ScopeID              any
	CanManageDescendants any
}

func UnmarshalTenantPrincipal(data []byte) TenantPrincipal {
	offset := 0
	var tp TenantPrincipal
	tp.TenantID, offset = readString(data, offset)
	tp.PrincipalID, offset = readString(data, offset)
	tp.RoleID, offset = readString(data, offset)
	tp.NamespaceID, offset = readString(data, offset)
	tp.ScopeID, offset = readString(data, offset)
	tp.CanManageDescendants = data[offset] == 1

	return tp
}

func readString(data []byte, offset int) (any, int) {
	length := int(data[offset]) | int(data[offset+1])<<8
	offset += 2
	return bytesToString(data[offset : offset+length]), offset + length
}

func bytesToString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

// MarshalTenantPrincipal encodes a TenantPrincipal into a binary string.
func MarshalTenantPrincipal(tp TenantPrincipal) ([]byte, error) {
	buffer := make([]byte, 0, 2*5+len(tp.TenantID.(string))+len(tp.PrincipalID.(string))+len(tp.RoleID.(string))+len(tp.NamespaceID.(string))+len(tp.ScopeID.(string))+1)
	buffer = writeString(buffer, tp.TenantID.(string))
	buffer = writeString(buffer, tp.PrincipalID.(string))
	buffer = writeString(buffer, tp.RoleID.(string))
	buffer = writeString(buffer, tp.NamespaceID.(string))
	buffer = writeString(buffer, tp.ScopeID.(string))
	if tp.CanManageDescendants.(bool) {
		buffer = append(buffer, 1)
	} else {
		buffer = append(buffer, 0)
	}
	return buffer, nil
}

func writeString(buffer []byte, s string) []byte {
	length := uint16(len(s))
	buffer = append(buffer, byte(length), byte(length>>8))
	buffer = append(buffer, s...)
	return buffer
}

func BenchmarkMarshal(b *testing.B) {
	tp := TenantPrincipal{
		TenantID:             "tenant123",
		PrincipalID:          "principal456",
		RoleID:               "role789",
		NamespaceID:          "namespaceABC",
		ScopeID:              "scopeDEF",
		CanManageDescendants: true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MarshalTenantPrincipal(tp)
	}
}

func BenchmarkUnmarshal(b *testing.B) {
	// Prepare the marshaled data from a valid TenantPrincipal instance.
	tp := TenantPrincipal{
		TenantID:             "tenant123",
		PrincipalID:          "principal456",
		RoleID:               "role789",
		CanManageDescendants: true,
	}
	principal, _ := MarshalTenantPrincipal(tp)
	fmt.Println(len(principal))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		UnmarshalTenantPrincipal(principal)
	}
}
